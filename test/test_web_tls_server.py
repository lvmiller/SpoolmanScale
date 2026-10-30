"""Exercise production server scheduling and ticket-init failure boundaries.

Compile the complete private server class against deterministic transport peers;
no HTTP/TLS implementation is simulated beyond those external boundaries.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).parents[1]
server = (root / "src/web/web_server.cpp").read_text()
server = server[server.index("#define WEB_IDLE_CLIENT_MS"):server.index("static ScaleWebServer https_server")]
identity = (root / "src/web/web_tls_identity.cpp").read_text()
configure = identity[identity.index("static void configureServer()"):identity.index("static void loadIdentity()")]
prelude = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
using String=std::string;
using PGM_P=const char *;
#define ESP_ARDUINO_VERSION_MAJOR 3
#define HTTP_MAX_SEND_WAIT 5000
#define CONTENT_LENGTH_NOT_SET size_t(-2)
uint32_t nowMs=0;
uint32_t millis(){return nowMs;}
void delay(unsigned n){nowMs+=n;}
void yield(){}
template<class... Args> void logSDf(const char *,Args...){}
using esp_err_t=int;
constexpr int ESP_OK=0;
struct Ticket {int key=42;};
struct esp_tls_cfg_server_t {
 const unsigned char *servercert_buf=nullptr,*serverkey_buf=nullptr;
 size_t servercert_bytes=0,serverkey_bytes=0;
 Ticket *ticket_ctx=nullptr;
};
bool ticketFailure=true;
int ticketInits=0;
int esp_tls_cfg_server_session_tickets_init(esp_tls_cfg_server_t *cfg){
 ++ticketInits;
 cfg->ticket_ctx=new Ticket;
 if(ticketFailure){delete cfg->ticket_ctx;return -1;} // IDF leaves the freed pointer in cfg.
 return ESP_OK;
}
const char *esp_err_to_name(int){return "injected failure";}
String s_cert="certificate",s_key="key";
esp_tls_cfg_server_t s_cfg;
bool s_tickets_attempted=false;
esp_tls_cfg_server_t *webTlsServerConfig(){return &s_cfg;}
struct Address {String toString()const{return "192.0.2.5";}};
class NetworkClient {
 public:
 bool live=false;
 explicit operator bool()const{return live;}
 virtual ~NetworkClient()=default;
 virtual int available(){return 0;}
 virtual uint8_t connected(){return live;}
 virtual void stop(){live=false;}
 void setTimeout(unsigned){}
 size_t print(const char *){return 0;}
 Address remoteIP()const{return {};}
};
using WiFiClient=NetworkClient;
bool acceptNext=false,queued=false;
class NetworkServer {
 public:
 NetworkClient accept(){NetworkClient c;c.live=acceptNext;acceptNext=false;return c;}
 bool hasClient(){return queued;}
 void setNoDelay(bool){}
};
bool cipher=true,payload=false;
int handshakeResult=1,stops=0,requests=0;
class WebTlsClient:public NetworkClient {
 bool started=false;
 public:
 bool begin(NetworkClient c,esp_tls_cfg_server_t *){live=c.live;started=false;return live;}
 int handshakeStep(){started=started||cipher;return started?handshakeResult:0;}
 bool handshakeStarted()const{return started;}
 int available()override{return payload?1:0;}
 size_t write(const uint8_t *,size_t n){return n;}
 void stop()override{if(live)++stops;live=false;}
};
class WebPlainHttpClient:public NetworkClient {
 public:
 explicit WebPlainHttpClient(NetworkClient&){}
 bool begin(){return true;}
 int method(){return 0;}
};
class WebServer {
 protected:
 enum State {HC_NONE,HC_WAIT_READ};
 State _currentStatus=HC_NONE;
 NetworkClient _currentClient;
 NetworkServer _server;
 bool _nullDelay=false;
 uint32_t _statusChange=0;
 std::unique_ptr<int> _currentUpload,_currentRaw;
 size_t _contentLength=0;
 int _responseCode=0,_currentMethod=0;
 String _hostHeader;
 bool _parseRequest(NetworkClient&){return true;}
 void _handleRequest(){++requests;}
 void _clearResponseHeaders(){}
 virtual size_t _currentClientWrite(const char *,size_t n){return n;}
 virtual size_t _currentClientWrite_P(PGM_P,size_t n){return n;}
 public:
 explicit WebServer(int){}
 virtual ~WebServer()=default;
 virtual void handleClient(){}
 virtual NetworkClient &client(){return _currentClient;}
 virtual void close(){}
 String uri()const{return "/";}
};
'''
main = r'''
void reset(uint32_t time=0){
 nowMs=time;acceptNext=true;queued=false;cipher=true;payload=false;
 handshakeResult=1;stops=0;requests=0;
}
int main(int argc,char **argv){
 assert(argc==2);
 const std::string mode=argv[1];
 if(mode=="tickets"){
   configureServer();
   assert(!s_cfg.ticket_ctx); // Later sessions must not dereference the freed context.
   configureServer();assert(!s_cfg.ticket_ctx && ticketInits==1);
   s_tickets_attempted=false;ticketFailure=false;
   configureServer();assert(s_cfg.ticket_ctx && s_cfg.ticket_ctx->key==42);
   auto *context=s_cfg.ticket_ctx;configureServer();assert(s_cfg.ticket_ctx==context);
   delete s_cfg.ticket_ctx;
 }else if(mode=="request"){
   for(auto start:{uint32_t(0),UINT32_MAX-100}){
     reset(start);ScaleWebServer s(443,true);s.handleClient(); // Finished sent.
     queued=true;nowMs=start+10;s.handleClient();assert(stops==0);
     nowMs=start+200;payload=true;s.handleClient();assert(requests==1 && stops==1);
   }
 }else if(mode=="silent"){
   for(bool queue:{false,true}){
     reset(UINT32_MAX-100);cipher=false;ScaleWebServer s(443,true);s.handleClient();
     queued=queue;nowMs+=queue?300:1001;s.handleClient();assert(stops==1 && requests==0);
   }
 }else if(mode=="deadlines"){
   reset();handshakeResult=0;ScaleWebServer active(443,true);active.handleClient();
   queued=true;nowMs=1600;active.handleClient();assert(stops==0);
   nowMs=2001;active.handleClient();assert(stops==1);
   reset();ScaleWebServer idle(443,true);idle.handleClient();
   nowMs=1001;idle.handleClient();assert(stops==1);
   reset();handshakeResult=-123;ScaleWebServer aborted(443,true);aborted.handleClient();assert(stops==1);
 }else assert(false);
 puts(("TLS server: "+mode+" passed").c_str());
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp, binary = Path(tmp) / "test.cpp", Path(tmp) / "test"
    cpp.write_text(prelude + configure + server + main)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(binary)], check=True)
    results = [subprocess.run([str(binary), case], timeout=10).returncode for case in ("tickets", "request", "silent", "deadlines")]
    assert all(code == 0 for code in results), results
