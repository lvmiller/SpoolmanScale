"""Exercise production TLS buffering and retry contracts with scripted esp-tls I/O."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
headers = {
    "NetworkClient.h": r'''#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <memory>
#include <unistd.h>
extern uint32_t nowMs;
extern bool ciphertext;
inline uint32_t millis() { return nowMs; }
inline void delay(unsigned n) {nowMs+=n;}
class NetworkClient {
  struct Handle { int fd; ~Handle() {if(fd>=0)::close(fd);} };
  std::shared_ptr<Handle> h;
 public:
  NetworkClient() = default;
  explicit NetworkClient(int fd):h(new Handle{fd}) {}
  virtual ~NetworkClient() = default;
  virtual int available() {return ciphertext?1:0;}
  virtual int read() {return -1;}
  virtual int read(uint8_t *,size_t) {return 0;}
  virtual int peek() {return -1;}
  virtual size_t write(uint8_t) {return 0;}
  virtual size_t write(const uint8_t *,size_t) {return 0;}
  virtual uint8_t connected() {return fd()>=0;}
  virtual void stop() {if(h && h->fd>=0){::close(h->fd);h->fd=-1;}}
  virtual int fd() const {return h?h->fd:-1;}
  void setTimeout(unsigned) {}
  void clear() {} // Default base has no socket/RX buffer, matching Arduino.
};
''',
    "WebServer.h": "#pragma once\n#define HTTP_MAX_SEND_WAIT 5000\n",
    "mbedtls/ssl.h": "#pragma once\nstruct mbedtls_ssl_context {};\ninline int mbedtls_ssl_close_notify(mbedtls_ssl_context *) {return 0;}\n",
    "esp_tls.h": r'''#pragma once
#include <string>
#include <algorithm>
#include <cstring>
#include <cstddef>
#include "mbedtls/ssl.h"
constexpr int ESP_OK=0, ESP_TLS_ERR_SSL_WANT_READ=-0x6900, ESP_TLS_ERR_SSL_WANT_WRITE=-0x6880;
struct esp_tls_cfg_server_t {};
struct esp_tls_t { size_t offset=0; int reads=0, writes=0, hs=0; mbedtls_ssl_context ssl; };
extern std::string input, output;
extern bool eof, stalled, initFail, handshakeFail;
extern int sessions;
inline esp_tls_t *esp_tls_init() {++sessions; return new esp_tls_t;}
inline int esp_tls_server_session_init(esp_tls_cfg_server_t *,int,esp_tls_t *) {return initFail?-1:0;}
inline int esp_tls_server_session_continue_async(esp_tls_t *t) {
  if(handshakeFail)return -123;
  if(!ciphertext && t->hs==0)return ESP_TLS_ERR_SSL_WANT_READ;
  return ++t->hs<3?ESP_TLS_ERR_SSL_WANT_READ:0;
}
inline void esp_tls_server_session_delete(esp_tls_t *t) {--sessions; delete t;}
inline void *esp_tls_get_ssl_context(esp_tls_t *t) {return &t->ssl;}
inline int esp_tls_get_bytes_avail(esp_tls_t *) {return 0;} // Ciphertext may still be waiting for a read.
inline int esp_tls_conn_read(esp_tls_t *t,void *p,size_t n) {
  if(++t->reads%5==0) return ESP_TLS_ERR_SSL_WANT_READ;
  if(t->offset==input.size()) return eof?0:ESP_TLS_ERR_SSL_WANT_READ;
  n=std::min({n,input.size()-t->offset,size_t(137)});
  memcpy(p,input.data()+t->offset,n); t->offset+=n; return (int)n;
}
inline int esp_tls_conn_write(esp_tls_t *t,const void *p,size_t n) {
  if(stalled || ++t->writes%3==0) return t->writes%2?ESP_TLS_ERR_SSL_WANT_WRITE:ESP_TLS_ERR_SSL_WANT_READ;
  n=std::min(n,size_t(509)); output.append((const char *)p,n); return (int)n;
}
''',
}
source = r'''
#include "web/web_tls_client.h"
#include <cassert>
#include <fcntl.h>
#include <cstdio>
std::string input, output;
bool eof=false, stalled=false, initFail=false, handshakeFail=false;
bool ciphertext=true;
int sessions=0;
uint32_t nowMs=0;
int main() {
  esp_tls_cfg_server_t cfg;
  WebTlsClient c;
  uint8_t buf[2048];
  assert(c.read(buf,sizeof(buf))==-1);
  assert(c.begin(NetworkClient(open("/dev/null",O_RDONLY)),&cfg));
  assert(fcntl(c.fd(),F_GETFL)&O_NONBLOCK);
  ciphertext=false;
  assert(c.handshakeStep()==0 && !c.handshakeStarted());
  ciphertext=true;
  assert(c.handshakeStep()==0 && c.handshakeStarted());
  ciphertext=false; // WANT_READ must not turn an active handshake back into a spare.
  assert(c.handshakeStep()==0 && c.handshakeStarted() && c.handshakeStep()==1);
  ciphertext=true;
  assert(c.read(buf,sizeof(buf))==0 && c.read()==-1 && c.peek()==-1);
  input="abc";
  assert(c.available()==3 && c.peek()=='a'); c.clear();
  assert(c.read()=='a' && c.read(buf,sizeof(buf))==2);
  assert(buf[0]=='b' && buf[1]=='c');
  c.stop(); assert(sessions==0 && c.fd()==-1 && !c.connected() && !c.handshakeStarted());
  input.resize(3600000);
  for(size_t i=0;i<input.size();++i) input[i]=char(i%251);
  assert(c.begin(NetworkClient(open("/dev/null",O_RDONLY)),&cfg));
  // Firmware's byte-at-a-time parser must see every byte despite WANT_READ.
  size_t received=0;
  while(received<input.size()) {int b=c.read(); if(b<0)continue; assert(b==(unsigned char)input[received++]);}
  eof=true;
  while(c.connected()) c.available();
  assert(c.read(buf,sizeof(buf))==-1);
  c.stop(); eof=false; input.clear();
  assert(c.begin(NetworkClient(open("/dev/null",O_RDONLY)),&cfg));
  std::string screenshot(300000,'x');
  assert(c.write((const uint8_t *)screenshot.data(),screenshot.size())==screenshot.size());
  assert(output==screenshot);
  stalled=true; nowMs=0xFFFFFF00;
  const uint32_t start=nowMs;
  assert(c.write((const uint8_t *)"x",1)==0);
  assert(uint32_t(nowMs-start)>=5000 && uint32_t(nowMs-start)<=5001 && !c.connected());
  c.stop(); stalled=false;
  initFail=true;
  assert(!c.begin(NetworkClient(open("/dev/null",O_RDONLY)),&cfg));
  assert(sessions==0 && c.fd()==-1);
  initFail=false; handshakeFail=true;
  assert(c.begin(NetworkClient(open("/dev/null",O_RDONLY)),&cfg));
  assert(c.handshakeStep()==-123 && !c.connected()); c.stop();
  assert(sessions==0);
  puts("TLS client: buffering, 3.6 MB reads, 300 KB writes, timeout/wrap and cleanup passed");
}
'''
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    for name, text in headers.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    cpp, binary = tmp / "test.cpp", tmp / "test"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(tmp), "-I", str(root / "src"), str(cpp), str(root / "src/web/web_tls_client.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=20)
