#pragma once

#include <WebServer.h>

void registerPlainHttpRoutes(WebServer &srv);

// WebServer consumes POST bodies before onNotFound(). Present non-protocol
// requests to its header-only GET parser, then restore method() for refusal.
// The socket-free base also makes the parser's non-virtual clear() a no-op:
// it must not consume a body after the last header. FilaMan POSTs are unchanged.
class WebPlainHttpClient : public NetworkClient {
 public:
  explicit WebPlainHttpClient(NetworkClient &tcp) : _tcp(tcp) {}
  bool begin();
  HTTPMethod method() const { return _method; }
  int read() override;
  int read(uint8_t *buf, size_t size) override;
  int peek() override;
  int available() override;
  uint8_t connected() override { return _pos < _line.length() || _tcp.connected(); }
  size_t write(uint8_t b) override { return _tcp.write(b); }
  size_t write(const uint8_t *buf, size_t n) override { return _tcp.write(buf, n); }
  void stop() override { _tcp.stop(); }
  int fd() const override { return _tcp.fd(); }
  using NetworkClient::write;
 private:
  NetworkClient &_tcp;
  String _line;
  size_t _pos = 0;
  HTTPMethod _method = HTTP_ANY;
};
