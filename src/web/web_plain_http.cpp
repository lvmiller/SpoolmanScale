#include "web/web_plain_http.h"

#include <algorithm>
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "web/web_server.h"
#include "lang.h"

bool WebPlainHttpClient::begin() {
  const uint32_t start = millis();
  uint32_t lastData = start;
  while ((uint32_t)(millis() - start) < HTTP_MAX_DATA_WAIT &&
         (uint32_t)(millis() - lastData) < getTimeout()) {
    const int c = _tcp.read();
    if (c < 0) {
      if (!_tcp.connected()) return false;
      yield();
      continue;
    }
    lastData = millis();
    if (_line.length() >= WEBSERVER_MAX_LINE_LEN || !_line.concat((char)c)) return false;
    if (c != '\n') continue;
    const int first = _line.indexOf(' ');
    const int last = _line.indexOf(' ', first + 1);
    if (first <= 0 || last <= first + 1) return false;
    const String verb = _line.substring(0, first);
    _method = verb == "GET" ? HTTP_GET : verb == "HEAD" ? HTTP_HEAD :
              verb == "POST" ? HTTP_POST : HTTP_ANY;
    String path = _line.substring(first + 1, last);
    const int query = path.indexOf('?');
    if (query >= 0) path = path.substring(0, query);
    const bool protocol = _method == HTTP_POST &&
      (path == "/api/v1/rfid/scan-request" || path == "/api/v1/rfid/write");
    if (!protocol) _line = "GET" + _line.substring(first);
    return true;
  }
  return false;
}

int WebPlainHttpClient::read() {
  return _pos < _line.length() ? (unsigned char)_line[_pos++] : _tcp.read();
}
int WebPlainHttpClient::peek() {
  return _pos < _line.length() ? (unsigned char)_line[_pos] : _tcp.peek();
}
int WebPlainHttpClient::available() { return (int)(_line.length() - _pos) + _tcp.available(); }
int WebPlainHttpClient::read(uint8_t *buf, size_t size) {
  const size_t n = std::min(size, _line.length() - _pos);
  memcpy(buf, _line.c_str() + _pos, n);
  _pos += n;
  const int tail = n < size ? _tcp.read(buf + n, size - n) : 0;
  return tail > 0 ? (int)n + tail : n ? (int)n : tail;
}

void registerPlainHttpRoutes(WebServer &srv) {
  srv.onNotFound([&srv]() {
    if (!webMasterEnabled()) {
      srv.send(403, "text/plain; charset=utf-8", T(STR_W_OFF_BODY));
      return;
    }
    if (!webServerIsListening()) {
      srv.send(503, "text/plain", "HTTPS unavailable");
      return;
    }
    if (srv.method() != HTTP_GET && srv.method() != HTTP_HEAD) {
      webLogRefusal(srv, "plain http");
      srv.send(403, "text/plain; charset=utf-8", T(STR_W_HTTPS_ONLY));
      return;
    }
    const String path = srv.uri();
    if (!path.startsWith("/")) {
      srv.send(400, "text/plain", "Bad Request");
      return;
    }
    String host = srv.hostHeader();
    const int colon = host.indexOf(':');
    if (colon >= 0) host = host.substring(0, colon);
    host.trim();
    host.toLowerCase();
    if (!host.length() || !webHostIsOurs(host)) host = wifiManagerLocalIP().toString();
    // Deliberately omit the query, which may carry old plaintext credentials.
    srv.sendHeader("Location", "https://" + host + path);
    srv.send(302, "text/plain", "");
  });
}
