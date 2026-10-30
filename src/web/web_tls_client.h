#pragma once

#include <NetworkClient.h>
#include <esp_tls.h>

// The base stays socket-free: WebServer's non-virtual clear() is a no-op.
// The accepted TCP client alone owns the descriptor; esp-tls only borrows it.
class WebTlsClient : public NetworkClient {
 public:
  WebTlsClient() = default;
  WebTlsClient(const WebTlsClient &) = delete;
  WebTlsClient &operator=(const WebTlsClient &) = delete;
  ~WebTlsClient() override { stop(); }
  bool begin(NetworkClient tcp, esp_tls_cfg_server_t *cfg);
  // One non-blocking step: 1 done, 0 waiting, negative error.
  int handshakeStep();
  bool handshakeStarted() const { return _handshakeStarted; }
  int available() override;
  int read() override;
  int read(uint8_t *buf, size_t size) override;
  int peek() override;
  size_t write(uint8_t b) override;
  size_t write(const uint8_t *buf, size_t size) override;
  uint8_t connected() override;
  void stop() override;
  int fd() const override;
  using NetworkClient::write;
 private:
  bool fill();
  NetworkClient _tcp;
  esp_tls_t *_tls = nullptr;
  bool _failed = false;
  bool _handshakeStarted = false;
  uint8_t _rx[1024];
  uint16_t _rxPos = 0, _rxLen = 0;
};
