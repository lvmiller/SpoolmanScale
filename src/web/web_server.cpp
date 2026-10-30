#include "web/web_server.h"

#include <Arduino.h>
#include <WebServer.h>
#include <WiFi.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "services/remote_link.h"
#include "services/setup_portal.h"
#include "services/tag_write.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "web/web_assets.h"
#include "web/web_static.h"
#include "web/web_pages.h"
#include "web/web_portal.h"
#include "web/web_shell.h"
#include "web/web_plain_http.h"
#include "web/web_tls_client.h"
#include "web/web_tls_identity.h"

// ArduinoJson has to come after lang.h anywhere the T() macro is in scope.
// Nothing here includes lang.h, so the plain include is safe.
#include <ArduinoJson.h>
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// How long an accepted socket may stay silent before it is dropped. The
// library waits HTTP_MAX_DATA_WAIT, five seconds, and serves one connection
// at a time - so a socket a browser opened and never used (Chrome opens
// spares on hover and on navigation) parked every other request for those
// five seconds, and with the accept backlog at four the browser saw
// "site not reachable" in between. A real request follows the handshake
// within milliseconds on a LAN; a second is patience enough.
#define WEB_IDLE_CLIENT_MS 1000
#define WEB_TLS_HANDSHAKE_MS 2000

// The library's one-client flow with a short idle wait and an optional TLS
// transport. All response bytes go through the virtual write hooks.
class ScaleWebServer : public WebServer {
 public:
  ScaleWebServer(int port, bool tls) : WebServer(port), _useTls(tls) {}
  void onlyProtocolBodies() { _plainHttp = true; }
  NetworkClient &client() override { return _useTls ? _tlsClient : _currentClient; }
  void close() override {
    if (_useTls) dropTlsClient();
    WebServer::close();
  }

  // Nagle off for the accepted sockets: every reply here is small and the
  // browser waits for the last packet of it.
  void tune() { _server.setNoDelay(true); }

  void handleClient() override {
    if (_useTls) { handleTlsClient(); return; }
    if (_currentStatus == HC_NONE) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
      _currentClient = _server.accept();
#else
      _currentClient = _server.available();
#endif
      if (!_currentClient) {
        if (_nullDelay) delay(1);
        return;
      }
      _currentStatus = HC_WAIT_READ;
      _statusChange  = millis();
    }

    bool keepCurrentClient = false;
    bool callYield = false;

    if (_currentClient.connected() && _currentStatus == HC_WAIT_READ) {
      if (_currentClient.available()) {
        if (parsePlainClient()) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
          // Core 3 counts this timeout in milliseconds, and keeps the
          // response headers of every request in a list that the library's
          // own handleClient() empties. Left out, each request kept its
          // headers for good: about 170 bytes of internal heap per request.
          _currentClient.setTimeout(HTTP_MAX_SEND_WAIT);
          _contentLength = CONTENT_LENGTH_NOT_SET;
          _responseCode  = 0;
          _clearResponseHeaders();
#else
          _currentClient.setTimeout(HTTP_MAX_SEND_WAIT / 1000);
          _contentLength = CONTENT_LENGTH_NOT_SET;
#endif
          const String req_uri = uri();
          const uint32_t t0 = millis();
          _handleRequest();
          const uint32_t took = millis() - t0;
          if (took >= 300) {
            logSDf("[verbose] web: %s from %s took %u ms", req_uri.c_str(),
                   _currentClient.remoteIP().toString().c_str(), (unsigned)took);
          }
        }
      } else {
        // An idle socket keeps its second only while nobody is waiting behind
        // it. Browsers open connections on speculation and leave them empty;
        // one of those at the front of a one-client server held the tab the
        // user actually clicked for up to a second. hasClient() accepts the
        // next connection into the server's own slot, so nothing is lost by
        // asking.
        if (millis() - _statusChange <= WEB_IDLE_CLIENT_MS && !_server.hasClient())
          keepCurrentClient = true;
        callYield = true;
      }
    }

    if (!keepCurrentClient) {
      _currentClient = WiFiClient();
      _currentStatus = HC_NONE;
      _currentUpload.reset();
      _currentRaw.reset();
    }
    if (callYield) yield();
  }

 protected:
  size_t _currentClientWrite(const char *buf, size_t n) override {
    return _useTls ? _tlsClient.write((const uint8_t *)buf, n) : WebServer::_currentClientWrite(buf, n);
  }
  size_t _currentClientWrite_P(PGM_P buf, size_t n) override {
    return _useTls ? _tlsClient.write((const uint8_t *)buf, n) : WebServer::_currentClientWrite_P(buf, n);
  }

 private:
  const bool _useTls;
  bool _plainHttp = false;
  WebTlsClient _tlsClient;
  bool _tlsHandshaking = false;
  uint32_t _tlsHsMs = 0;

  bool parsePlainClient() {
    if (!_plainHttp) return _parseRequest(_currentClient);
    WebPlainHttpClient headers(_currentClient);
    if (!headers.begin()) {
      _currentClient.print("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      return false;
    }
    _hostHeader = "";
    const bool parsed = _parseRequest(headers);
    _currentMethod = headers.method();
    return parsed;
  }

  void dropTlsClient() {
    _tlsClient.stop();
    _tlsHandshaking = false;
    _currentStatus = HC_NONE;
    _currentUpload.reset();
    _currentRaw.reset();
  }

  void handleTlsClient() {
    if (_currentStatus == HC_NONE) {
      NetworkClient tcp = _server.accept();
      if (!tcp) {
        if (_nullDelay) delay(1);
        return;
      }
      if (!_tlsClient.begin(tcp, webTlsServerConfig())) return;
      _tlsHandshaking = true;
      _tlsHsMs = 0;
      _currentStatus = HC_WAIT_READ;
      _statusChange = millis();
    }
    if (_tlsHandshaking) {
      const uint32_t start = millis();
      const int result = _tlsClient.handshakeStep();
      _tlsHsMs += millis() - start;
      if (result == 1) {
        logSDf("[verbose] web: tls handshake %u ms from %s", (unsigned)_tlsHsMs,
               _tlsClient.remoteIP().toString().c_str());
        _tlsHandshaking = false;
        _statusChange = millis();
        return;
      }
      if (result == 0 && millis() - _statusChange <= WEB_TLS_HANDSHAKE_MS) return;
      if (result < 0)
        logSDf("[verbose] web: tls handshake failed (-0x%04X) from %s", (unsigned)-result,
               _tlsClient.remoteIP().toString().c_str());
      dropTlsClient();
      return;
    }
    bool keep = false;
    bool callYield = false;
    if (_tlsClient.connected() && _currentStatus == HC_WAIT_READ) {
      if (_tlsClient.available()) {
        if (_parseRequest(_tlsClient)) {
          _tlsClient.setTimeout(HTTP_MAX_SEND_WAIT);
          _contentLength = CONTENT_LENGTH_NOT_SET;
          _responseCode = 0;
          _clearResponseHeaders();
          const String req_uri = uri();
          const uint32_t start = millis();
          _handleRequest();
          const uint32_t took = millis() - start;
          if (took >= 300)
            logSDf("[verbose] web: %s from %s took %u ms", req_uri.c_str(),
                   _tlsClient.remoteIP().toString().c_str(), (unsigned)took);
        }
      } else {
        keep = millis() - _statusChange <= WEB_IDLE_CLIENT_MS && !_server.hasClient();
        callYield = true;
      }
    }
    if (!keep) dropTlsClient();
    if (callYield) yield();
  }
};

static ScaleWebServer https_server(443, true);
static bool https_server_running = false;
static bool https_routes_registered = false;
static ScaleWebServer http_server(80, false);
static bool http_server_running = false;
static bool http_routes_registered = false;

// While the WiFi setup portal runs, port 80 serves its form instead. The
// access point is the only network then, the main interface has nothing to
// offer on it, and its host check would refuse every request a phone sends.
// A server object of its own, because routes cannot be taken off one.
static ScaleWebServer portal_server(80, false);
static bool portal_server_running    = false;
static bool portal_routes_registered = false;

// True while the scale has to stay reachable for FilaMan's device protocol.
// In Spoolman and BamBuddy mode this is never true and nothing changes.
static bool remoteLinkNeedsServer() {
  return wifi_ok && backendIsFilaMan() && filamanDeviceToken()[0];
}

// The one condition that decides whether port 80 is open. The master switch
// owns it; the remote link can force it up on its own, because a user who
// switches the web interface off did not ask for FilaMan to stop being able
// to drive the scale. Everything except GATE_ALWAYS still answers 403 in
// that state, so nothing becomes reachable that the switch was meant to
// close.
static bool httpShouldRun() {
  return wifi_ok && (webMasterEnabled() || remoteLinkNeedsServer());
}

static bool httpsShouldRun() { return wifi_ok && webMasterEnabled(); }

static void registerHttpsRoutes();
static void registerHttpRoutes();
static const char *HDR_KEYS[] = { "Origin" };

// The origin the configured backend is served from: scheme, host and port,
// no path, the only form frame-ancestors accepts. Only FilaMan and BamBuddy
// get one, the two that can show the scale in a frame and the condition the
// card on the backend page uses: in Spoolman mode nothing embeds, so nothing
// is allowed to. Empty when the host holds anything a host and port are not
// made of: the value goes into a response header, where a space or a
// semicolon would change the policy.
static String backendFrameOrigin() {
  if (!backendIsFilaMan() && !backendIsBamBuddy()) return "";
  String base = backendBaseUrl();
  base.toLowerCase();
  String origin;
  if (base.startsWith("http://") || base.startsWith("https://")) {
    const int host_start = base.indexOf("://") + 3;   // past "://"
    const int path_start = base.indexOf('/', host_start);
    origin = (path_start < 0) ? base : base.substring(0, path_start);
    if ((int)origin.length() == host_start) origin = "";
    for (size_t i = host_start; i < origin.length(); i++) {
      const char c = origin[i];
      if (!isalnum((unsigned char)c) && c != '.' && c != ':' && c != '-') { origin = ""; break; }
    }
  }
  // Said once per address, not per request: the card on the backend page
  // promises that exactly this address embeds, so a refused one (an IPv6
  // literal, an underscore in the name) has to show up in the log.
  static String refused;
  if (!origin.length() && base.length() && base != refused) {
    refused = base;
    Serial.printf("Frame origin refused, backend address is not host:port: %s\n", base.c_str());
    logSDf("Frame origin refused, backend address is not host:port: %s", base.c_str());
  }
  return origin;
}

static void httpsEnsureRunning() {
  if (https_server_running) return;
  registerHttpsRoutes();
  // The headers webRequire() reads. Authorization is collected by the library
  // on its own; Origin has to be asked for, and asked for before begin().
  https_server.collectHeaders(HDR_KEYS, 1);
  https_server.begin();
  https_server.tune();
  https_server_running = true;
  char fp[96];
  webTlsFingerprint(fp, sizeof(fp), 0);
  Serial.printf("Web server listening: https://%s/ (certificate SHA-256 %s)\n",
                wifiManagerLocalIP().toString().c_str(), fp);
}

static void httpsEnsureStopped() {
  if (!https_server_running) return;
  https_server.stop();
  https_server_running = false;
  Serial.println("Web server stopped");
}

static void httpEnsureRunning() {
  if (http_server_running) return;
  registerHttpRoutes();
  http_server.onlyProtocolBodies();
  http_server.collectHeaders(HDR_KEYS, 1);
  http_server.begin();
  http_server.tune();
  http_server_running = true;
  Serial.println("Port 80 listening: FilaMan protocol, redirect to https");
}

static void httpEnsureStopped() {
  if (!http_server_running) return;
  http_server.stop();
  http_server_running = false;
  Serial.println("Port 80 stopped");
}

static void portalEnsureRunning() {
  if (portal_server_running) return;
  if (!portal_routes_registered) {
    portal_routes_registered = true;
    registerPortalRoutes(portal_server);
  }
  portal_server.begin();
  portal_server.tune();
  portal_server_running = true;
  Serial.printf("Setup portal listening: http://%s/\n", setupPortalIP().toString().c_str());
}

static void portalEnsureStopped() {
  if (!portal_server_running) return;
  portal_server.stop();
  portal_server_running = false;
  Serial.println("Setup portal stopped");
}

// Idempotent, called once a second from appLoop() and once more whenever a
// screen wants the state to settle now. The only owner of ports 80 and 443.
// The portal and plaintext server never bind port 80 at the same time.
void webServerSyncState() {
  if (setupPortalActive()) {
    httpsEnsureStopped();
    httpEnsureStopped();
    portalEnsureRunning();
    return;
  }
  portalEnsureStopped();
  if (httpsShouldRun() && webTlsIdentityEnsure()) httpsEnsureRunning();
  else httpsEnsureStopped();
  if (httpShouldRun()) httpEnsureRunning();
  else httpEnsureStopped();
}

bool webServerIsListening() { return https_server_running; }

// Registered exactly once. This used to run on every visit to the web screen,
// which appended another handler set to WebServer's list each time and never
// freed the previous ones - WebServer::stop() does not release them.
static void registerHttpsRoutes() {
  if (https_routes_registered) return;
  https_routes_registered = true;

  registerAssetRoutes(https_server);
  registerStaticRoutes(https_server);

  // Every page and every endpoint it owns, straight from the one table. The
  // page route itself is wrapped here so the gate check and the chrome happen
  // in one place and cannot be forgotten in a new page.
  for (size_t i = 0; i < WEB_PAGE_COUNT; i++) {
    // Captured as a pointer by value, not as a reference to the loop
    // variable. The descriptor itself lives in ROM either way, but a
    // by-value pointer says so at the capture and leaves nothing to reason
    // about once the loop has ended.
    const WebPage *pg = WEB_PAGES[i];
    https_server.on(pg->path, HTTP_GET, [pg]() {
      // A page that does not apply to this device is absent, not refused:
      // there is no backend page at all on Spoolman.
      if (pg->applies && !pg->applies()) {
        https_server.send(404, "text/plain", "Not found");
        return;
      }
      if (!webRequire(https_server, pg->gate, webPageLabel(*pg))) return;
      String html = webShellHead(webPageLabel(*pg));
      html += webShellHeader();
      html += webShellNav(pg->path);
      html += pg->body();
      html += webShellFoot();   // links and disclaimer close the page
      // No page of the scale inside somebody else's frame: a site on the
      // same network could otherwise lay its own buttons over Flash, Erase or
      // Restart and have a visitor click them.
      https_server.sendHeader("X-Frame-Options", "DENY");
      // The one exception is a FilaMan or BamBuddy backend set on the scale,
      // so its sidebar link or plugin page can show it. A browser that
      // knows frame-ancestors follows it and skips the DENY above; an older
      // one keeps refusing every frame.
      const String frame_origin = backendFrameOrigin();
      if (frame_origin.length()) {
        https_server.sendHeader("Content-Security-Policy", "frame-ancestors " + frame_origin);
      }
      https_server.send(200, "text/html", html);
    });
    if (pg->routes) pg->routes(https_server);
  }
}

static void registerHttpRoutes() {
  if (http_routes_registered) return;
  http_routes_registered = true;
  // The two FilaMan device endpoints. GATE_ALWAYS, the only level that ignores
  // the master switch: these have to answer whenever the scale is awake, that
  // is the whole point of keeping the socket up. What the gate does ask is
  // that the caller is the configured FilaMan server - see webRequire().
  //
  // FilaMan sends both fire and forget and waits five seconds, so nothing here
  // may block. A request is only parked and appLoop() picks it up, because the
  // NFC bus belongs to the loop task.

  // "Import from tag": whatever is on the reader is sent back on the next tick.
  http_server.on("/api/v1/rfid/scan-request", HTTP_POST, []() {
    if (!webRequire(http_server, GATE_ALWAYS, "FilaMan")) return;
    tagScanRequest();
    http_server.send(200, "application/json", "{\"status\":\"ok\"}");
  });


  http_server.on("/api/v1/rfid/write", HTTP_POST, []() {
    if (!webRequire(http_server, GATE_ALWAYS, "FilaMan")) return;
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, http_server.arg("plain"));
    if (err) {
      http_server.send(400, "application/json", "{\"status\":\"error\"}");
      return;
    }

    const int spool_id    = doc["spool_id"]    | 0;
    const int location_id = doc["location_id"] | 0;

    // FilaMan's backend can expand the trigger into a full record before
    // forwarding it, under either of two protocol names. Keep what it sent:
    // the server decided what belongs on the tag.
    //
    // It only does that with "write extended data" turned on in its admin
    // settings, which is off by default - so a bare trigger carrying nothing
    // but the id is the normal case, not an old server. The scale then builds
    // the record itself from the spool record, the same one the tag page
    // writes, and the setting stops mattering.
    const char *proto = doc["protocol"] | "";
    const bool has_record = !strcmp(proto, "openspool") || !strcmp(proto, "filaman");
    tagRemotePayloadSet(has_record ? http_server.arg("plain").c_str() : "",
                        spool_id);

    if (spool_id > 0) {
      remoteLinkSetPending(spool_id);
      http_server.send(200, "application/json", "{\"status\":\"ok\"}");
      return;
    }
    if (location_id > 0) {
      // Locations are a FilaMan concept the scale does not handle yet.
      // Turning the request down beats ignoring it: the web UI would
      // otherwise poll for a full minute before its own timeout.
      remote_link_reject_pending = true;
      http_server.send(200, "application/json", "{\"status\":\"ok\"}");
      return;
    }
    http_server.send(400, "application/json", "{\"status\":\"error\"}");
  });
  registerPlainHttpRoutes(http_server);
}

void handleOtaServerClient() {
  if (https_server_running)    https_server.handleClient();
  if (http_server_running)     http_server.handleClient();
  if (portal_server_running) portal_server.handleClient();
}
