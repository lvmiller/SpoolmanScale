"""Run plaintext redirect/refusal policy and the header-only request adapter."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).parents[1]
headers = {
"WebServer.h": r'''#pragma once
#include <string>
#include <map>
#include <functional>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
class String : public std::string {
 public:
 using std::string::string;
 using std::string::operator=;
 String(const std::string &s):std::string(s){}
 int indexOf(char c,int start=0)const {auto n=find(c,start); return n==npos?-1:int(n);}
 String substring(size_t a,size_t b=npos)const {return substr(a,b==npos?npos:b-a);}
 void trim(){auto a=find_first_not_of(" \t\r\n"); if(a==npos){clear();return;} *this=substr(a,find_last_not_of(" \t\r\n")-a+1);}
 void toLowerCase(){for(char &c:*this)c=std::tolower((unsigned char)c);}
 bool concat(char c){push_back(c);return true;}
};
extern uint32_t nowMs;
inline uint32_t millis(){return nowMs;}
inline void yield(){++nowMs;}
#define HTTP_MAX_DATA_WAIT 5000
#define WEBSERVER_MAX_LINE_LEN 8192
class NetworkClient {
 public:
 std::string wire; size_t pos=0;
 virtual ~NetworkClient()=default;
 virtual int read(){return pos<wire.size()?(unsigned char)wire[pos++]:-1;}
 virtual int read(uint8_t *b,size_t n){size_t i=0;for(;i<n && pos<wire.size();++i)b[i]=wire[pos++];return int(i);}
 virtual int peek(){return pos<wire.size()?(unsigned char)wire[pos]:-1;}
 virtual int available(){return int(wire.size()-pos);}
 virtual uint8_t connected(){return 1;}
 virtual size_t write(uint8_t){return 1;}
 virtual size_t write(const uint8_t*,size_t n){return n;}
 virtual void stop(){}
 virtual int fd()const{return 1;}
 void clear(){} // The adapter's base has no RX buffer.
};
enum HTTPMethod {HTTP_ANY,HTTP_GET,HTTP_HEAD,HTTP_POST,HTTP_PUT,HTTP_PATCH,HTTP_DELETE,HTTP_OPTIONS};
class WebServer {
 public:
 std::function<void()> handler;
 HTTPMethod verb=HTTP_GET;
 String host="192.0.2.5",path="/backend",body;
 int status=0;
 std::map<std::string,String> headers;
 void onNotFound(std::function<void()> f){handler=f;}
 HTTPMethod method(){return verb;}
 String hostHeader(){return host;}
 String uri(){return path;}
 void sendHeader(const char *k,const String &v){headers[k]=v;}
 void send(int n,const char*,const String &b){status=n;body=b;}
};
''',
"web/web_access.h":r'''#pragma once
#include <WebServer.h>
extern bool master;
inline bool webMasterEnabled(){return master;}
inline bool webHostIsOurs(const String &h){return h=="192.0.2.5" || h=="scale.local";}
inline void webLogRefusal(WebServer&,const char*){}
''',
"web/web_server.h":"#pragma once\nextern bool listening;\ninline bool webServerIsListening(){return listening;}\n",
"services/wifi_manager.h":r'''#pragma once
#include <WebServer.h>
struct IP {String toString(){return "192.0.2.5";}};
inline IP wifiManagerLocalIP(){return {};}
''',
"lang.h":"#pragma once\n#define T(x) #x\n",
}
source = r'''
#include "web/web_plain_http.h"
#include <cassert>
#include <cstdio>
bool master=true,listening=true;
uint32_t nowMs=0;
int main(){
 for(auto host:{"evil.example",""," :80","192.0.2.5:80"," SCALE.LOCAL:80 "}){
   WebServer s; s.host=host; registerPlainHttpRoutes(s); s.handler();
   assert(s.status==302);
   assert(s.headers["Location"]==(s.host==" SCALE.LOCAL:80 "?"https://scale.local/backend":"https://192.0.2.5/backend"));
 }
 for(auto method:{HTTP_POST,HTTP_PUT,HTTP_PATCH,HTTP_DELETE,HTTP_OPTIONS,HTTP_ANY}){
   WebServer s;s.verb=method;registerPlainHttpRoutes(s);s.handler();
   assert(s.status==403 && !s.headers.count("WWW-Authenticate") && !s.headers.count("Location"));
 }
 WebServer h;h.verb=HTTP_HEAD;registerPlainHttpRoutes(h);h.handler();assert(h.status==302);
 listening=false;WebServer down;registerPlainHttpRoutes(down);down.handler();assert(down.status==503);
 master=false;WebServer off;registerPlainHttpRoutes(off);off.handler();assert(off.status==403);
 for(auto path:{"/api/bambuddy/key","/api/v1/rfid/write","/api/v1/rfid/scan-request?x=1","/api/v1/rfid/write/"}){
   NetworkClient tcp;tcp.wire=std::string("POST ")+path+" HTTP/1.1\r\nHost: scale.local\r\nContent-Length: 6\r\n\r\nSECRET";
   WebPlainHttpClient client(tcp);assert(client.begin());
   std::string headers;
   while(headers.size()<4 || headers.substr(headers.size()-4)!="\r\n\r\n"){
     int c=client.read();assert(c>=0);headers+=char(c);
   }
   client.clear();assert(tcp.wire.substr(tcp.pos)=="SECRET");
   const bool protocol=std::string(path)=="/api/v1/rfid/write" || std::string(path)=="/api/v1/rfid/scan-request?x=1";
   assert(headers.rfind(protocol?"POST ":"GET ",0)==0);
   assert(client.method()==HTTP_POST);
 }
 NetworkClient silent; WebPlainHttpClient waiting(silent);assert(!waiting.begin() && nowMs<=5001);
 puts("plain HTTP: local redirects, refusal precedence, no challenge and body isolation passed");
}
'''
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    for name, text in headers.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (tmp / "test.cpp").write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(tmp), "-I", str(root / "src"), str(tmp / "test.cpp"), str(root / "src/web/web_plain_http.cpp"), "-o", str(tmp / "test")], check=True)
    subprocess.run([str(tmp / "test")], check=True, timeout=10)
