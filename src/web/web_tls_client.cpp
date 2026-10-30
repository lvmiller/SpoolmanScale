#include "web/web_tls_client.h"

#include <WebServer.h>
#include <algorithm>
#include <fcntl.h>
#include <mbedtls/ssl.h>

bool WebTlsClient::begin(NetworkClient tcp, esp_tls_cfg_server_t *cfg) {
  stop();
  _tcp = tcp;
  const int flags = fcntl(_tcp.fd(), F_GETFL, 0);
  if (flags < 0 || fcntl(_tcp.fd(), F_SETFL, flags | O_NONBLOCK) < 0) {
    _tcp.stop();
    return false;
  }
  _tls = esp_tls_init();
  if (!_tls || esp_tls_server_session_init(cfg, _tcp.fd(), _tls) != ESP_OK) {
    // Setup may not have initialized an SSL context, so do not close_notify.
    if (_tls) esp_tls_server_session_delete(_tls);
    _tls = nullptr;
    _tcp.stop();
    return false;
  }
  _rxPos = _rxLen = 0;
  _failed = false;
  setTimeout(1000);
  return true;
}

int WebTlsClient::handshakeStep() {
  if (!_tls || _failed) return -1;
  if (!_handshakeStarted) {
    // Distinguish a TCP-only preconnect from an in-flight TLS handshake.
    if (_tcp.available() <= 0) {
      if (_tcp.connected()) return 0;
      _failed = true;
      return -1;
    }
    _handshakeStarted = true;
  }
  const int ret = esp_tls_server_session_continue_async(_tls);
  if (ret == 0) return 1;
  if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) return 0;
  _failed = true;
  return ret;
}

bool WebTlsClient::fill() {
  if (_rxPos < _rxLen) return true;
  if (!_tls || _failed) return false;
  const int n = esp_tls_conn_read(_tls, _rx, sizeof(_rx));
  if (n > 0) {
    _rxPos = 0;
    _rxLen = (uint16_t)n;
    return true;
  }
  if (n != ESP_TLS_ERR_SSL_WANT_READ && n != ESP_TLS_ERR_SSL_WANT_WRITE) _failed = true;
  return false;
}

int WebTlsClient::available() {
  if (!_tls || _failed) return 0;
  int n = _rxLen - _rxPos + std::max(0, esp_tls_get_bytes_avail(_tls));
  if (!n) {
    fill();
    n = _rxLen - _rxPos + std::max(0, esp_tls_get_bytes_avail(_tls));
  }
  return n;
}

int WebTlsClient::read() { return fill() ? _rx[_rxPos++] : -1; }
int WebTlsClient::peek() { return fill() ? _rx[_rxPos] : -1; }

int WebTlsClient::read(uint8_t *buf, size_t size) {
  size_t used = 0;
  while (used < size && fill()) {
    const size_t n = std::min(size - used, (size_t)(_rxLen - _rxPos));
    memcpy(buf + used, _rx + _rxPos, n);
    _rxPos += n;
    used += n;
  }
  // NetworkClient::readBytes distinguishes "wait" (0) from "closed" (-1).
  return used ? (int)used : (!_tls || _failed ? -1 : 0);
}

size_t WebTlsClient::write(uint8_t b) { return write(&b, 1); }

size_t WebTlsClient::write(const uint8_t *buf, size_t size) {
  if (!_tls || _failed) return 0;
  size_t sent = 0;
  uint32_t progress = millis();
  while (sent < size) {
    const int n = esp_tls_conn_write(_tls, buf + sent, size - sent);
    if (n > 0) {
      sent += (size_t)n;
      progress = millis();
    } else if ((n == ESP_TLS_ERR_SSL_WANT_WRITE || n == ESP_TLS_ERR_SSL_WANT_READ) &&
               (uint32_t)(millis() - progress) < HTTP_MAX_SEND_WAIT) {
      delay(1);
    } else {
      _failed = true;
      break;
    }
  }
  return sent;
}

uint8_t WebTlsClient::connected() {
  return _tls && !_failed && (_rxPos < _rxLen || esp_tls_get_bytes_avail(_tls) > 0 || _tcp.connected());
}

int WebTlsClient::fd() const { return _tcp.fd(); }

void WebTlsClient::stop() {
  if (_tls) {
    (void)mbedtls_ssl_close_notify((mbedtls_ssl_context *)esp_tls_get_ssl_context(_tls));
    esp_tls_server_session_delete(_tls);
    _tls = nullptr;
  }
  _tcp.stop();
  _rxPos = _rxLen = 0;
  _failed = false;
  _handshakeStarted = false;
}
