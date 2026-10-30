#include "web/web_tls_identity.h"

#include <Arduino.h>
#include <esp_err.h>
#include <memory>
#include <time.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/device_name.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"

// Apple clients reject server certificates valid for more than 825 days.
#define WEB_TLS_VALID_DAYS 730
#define WEB_TLS_RENEW_MARGIN_S (30UL * 86400UL)
#define WEB_TLS_RETRY_MS (24UL * 3600UL * 1000UL)
#define WEB_TLS_CLOCK_FLOOR 1767225600

static String s_key, s_cert;
static uint32_t s_until = 0;
static unsigned char s_fp[32];
static esp_tls_cfg_server_t s_cfg = {};
static bool s_loaded = false, s_attempted = false, s_tickets_attempted = false;
static uint32_t s_attempt_ms = 0;

// All mbedTLS allocations are released on every error path, including a
// failed renewal. The currently served PEMs are not touched until success.
struct IdentityWork {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_pk_context key;
  mbedtls_x509_crt cert;
  mbedtls_x509write_cert writer;
  IdentityWork() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);
    mbedtls_pk_init(&key);
    mbedtls_x509_crt_init(&cert);
    mbedtls_x509write_crt_init(&writer);
  }
  ~IdentityWork() {
    mbedtls_x509write_crt_free(&writer);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
  }
  int seed() {
    const char *personal = "spoolscale-tls";
    return mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)personal, strlen(personal));
  }
};

static void configureServer() {
  s_cfg.servercert_buf = (const unsigned char *)s_cert.c_str();
  s_cfg.servercert_bytes = s_cert.length() + 1;
  s_cfg.serverkey_buf = (const unsigned char *)s_key.c_str();
  s_cfg.serverkey_bytes = s_key.length() + 1;
  if (!s_tickets_attempted) {
    s_tickets_attempted = true;
    const esp_err_t err = esp_tls_cfg_server_session_tickets_init(&s_cfg);
    if (err != ESP_OK)
      logSDf("Web: TLS session tickets unavailable (%s)", esp_err_to_name(err));
  }
}

static void loadIdentity() {
  String key = prefsGetString("tls_key");
  String cert = prefsGetString("tls_crt");
  const uint32_t until = prefsGetUInt("tls_until", 0);
  if (!key.length() && !cert.length() && !until) return;
  IdentityWork w;
  if (key.length() && cert.length() && until && w.seed() == 0 &&
      mbedtls_x509_crt_parse(&w.cert, (const unsigned char *)cert.c_str(), cert.length() + 1) == 0 &&
      mbedtls_pk_parse_key(&w.key, (const unsigned char *)key.c_str(), key.length() + 1,
                           nullptr, 0, mbedtls_ctr_drbg_random, &w.rng) == 0 &&
      mbedtls_pk_check_pair(&w.cert.pk, &w.key, mbedtls_ctr_drbg_random, &w.rng) == 0 &&
      mbedtls_sha256(w.cert.raw.p, w.cert.raw.len, s_fp, 0) == 0) {
    s_key = std::move(key);
    s_cert = std::move(cert);
    s_until = until;
    configureServer();
  } else {
    logSD("Web: stored TLS identity unusable, creating a new one");
  }
}

static int createIdentity(time_t now) {
  IdentityWork w;
  int ret = w.seed();
  if (ret) return ret;
  ret = mbedtls_pk_setup(&w.key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (ret) return ret;
  ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(w.key),
                           mbedtls_ctr_drbg_random, &w.rng);
  if (ret) return ret;

  mbedtls_x509write_crt_set_version(&w.writer, MBEDTLS_X509_CRT_VERSION_3);
  mbedtls_x509write_crt_set_md_alg(&w.writer, MBEDTLS_MD_SHA256);
  mbedtls_x509write_crt_set_subject_key(&w.writer, &w.key);
  mbedtls_x509write_crt_set_issuer_key(&w.writer, &w.key);
  String subject = String("CN=SpoolmanScale ") + wifiManagerDeviceId() + ",O=SpoolmanScale";
  ret = mbedtls_x509write_crt_set_subject_name(&w.writer, subject.c_str());
  if (ret) return ret;
  ret = mbedtls_x509write_crt_set_issuer_name(&w.writer, subject.c_str());
  if (ret) return ret;
  unsigned char serial[16];
  ret = mbedtls_ctr_drbg_random(&w.rng, serial, sizeof(serial));
  if (ret) return ret;
  serial[0] = (serial[0] & 0x7F) | 0x01;
  ret = mbedtls_x509write_crt_set_serial_raw(&w.writer, serial, sizeof(serial));
  if (ret) return ret;

  const time_t before = now >= WEB_TLS_CLOCK_FLOOR ? now - 86400 : WEB_TLS_CLOCK_FLOOR;
  const time_t after = before + WEB_TLS_VALID_DAYS * 86400UL;
  char notBefore[16], notAfter[16];
  struct tm t;
  gmtime_r(&before, &t);
  strftime(notBefore, sizeof(notBefore), "%Y%m%d%H%M%S", &t);
  gmtime_r(&after, &t);
  strftime(notAfter, sizeof(notAfter), "%Y%m%d%H%M%S", &t);
  ret = mbedtls_x509write_crt_set_validity(&w.writer, notBefore, notAfter);
  if (ret) return ret;
  ret = mbedtls_x509write_crt_set_basic_constraints(&w.writer, 0, -1);
  if (ret) return ret;
  ret = mbedtls_x509write_crt_set_key_usage(&w.writer, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
  if (ret) return ret;
  mbedtls_asn1_sequence usage = {};
  usage.buf.tag = MBEDTLS_ASN1_OID;
  usage.buf.p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH;
  usage.buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
  ret = mbedtls_x509write_crt_set_ext_key_usage(&w.writer, &usage);
  if (ret) return ret;
  char dns[DEVICE_FQDN_MAX + 1];
  deviceMdnsName(dns, sizeof(dns));
  mbedtls_x509_san_list san = {};
  san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
  san.node.san.unstructured_name.p = (unsigned char *)dns;
  san.node.san.unstructured_name.len = strlen(dns);
  ret = mbedtls_x509write_crt_set_subject_alternative_name(&w.writer, &san);
  if (ret) return ret;
  ret = mbedtls_x509write_crt_set_subject_key_identifier(&w.writer);
  if (ret) return ret;

  std::unique_ptr<unsigned char, decltype(&free)> cert((unsigned char *)malloc(2048), free);
  std::unique_ptr<unsigned char, decltype(&free)> key((unsigned char *)malloc(512), free);
  if (!cert || !key) return MBEDTLS_ERR_X509_ALLOC_FAILED;
  ret = mbedtls_x509write_crt_pem(&w.writer, cert.get(), 2048, mbedtls_ctr_drbg_random, &w.rng);
  if (ret) return ret;
  ret = mbedtls_pk_write_key_pem(&w.key, key.get(), 512);
  if (ret) return ret;
  ret = mbedtls_x509_crt_parse(&w.cert, cert.get(), strlen((char *)cert.get()) + 1);
  if (ret) return ret;
  unsigned char fp[32];
  ret = mbedtls_sha256(w.cert.raw.p, w.cert.raw.len, fp, 0);
  if (ret) return ret;
  String nextKey((char *)key.get()), nextCert((char *)cert.get());
  if (nextKey.length() != strlen((char *)key.get()) ||
      nextCert.length() != strlen((char *)cert.get())) return MBEDTLS_ERR_X509_ALLOC_FAILED;
  s_key = std::move(nextKey);
  s_cert = std::move(nextCert);
  s_until = (uint32_t)after;
  memcpy(s_fp, fp, sizeof(s_fp));
  configureServer();
  // Attempt all three writes even if one fails. Invalid partial pairs are
  // rejected at the next boot; this boot still has a complete RAM identity.
  const bool keySaved = prefsPutString("tls_key", s_key.c_str());
  const bool certSaved = prefsPutString("tls_crt", s_cert.c_str());
  const bool untilSaved = prefsPutUInt("tls_until", s_until);
  if (!keySaved || !certSaved || !untilSaved)
    logSD("Web: TLS identity not saved, the next boot creates another");
  return 0;
}

bool webTlsIdentityEnsure() {
  if (!s_loaded) { s_loaded = true; loadIdentity(); }
  const bool have = s_cert.length() != 0;
  const time_t now = time(nullptr);
  if (have && (now < WEB_TLS_CLOCK_FLOOR || now + WEB_TLS_RENEW_MARGIN_S < s_until)) return true;
  const uint32_t ms = millis();
  if (!wifi_ok || (s_attempted && (uint32_t)(ms - s_attempt_ms) < WEB_TLS_RETRY_MS)) return have;
  s_attempted = true;
  s_attempt_ms = ms;
  const int ret = createIdentity(now);
  if (ret) {
    logSDf("Web: TLS certificate could not be created (-0x%04X)", (unsigned)-ret);
  } else {
    char fp[96];
    webTlsFingerprint(fp, sizeof(fp), 0);
    logSDf("Web: TLS certificate %s, SHA-256 %s", have ? "renewed" : "created", fp);
  }
  return s_cert.length() != 0;
}

esp_tls_cfg_server_t *webTlsServerConfig() { return s_cert.length() ? &s_cfg : nullptr; }

bool webTlsFingerprint(char *out, size_t len, uint8_t pairs_per_line) {
  if (len) out[0] = '\0';
  if (len < 96 || !s_cert.length()) return false;
  static const char hex[] = "0123456789ABCDEF";
  char *p = out;
  for (size_t i = 0; i < sizeof(s_fp); ++i) {
    *p++ = hex[s_fp[i] >> 4];
    *p++ = hex[s_fp[i] & 15];
    if (i + 1 < sizeof(s_fp))
      *p++ = pairs_per_line && (i + 1) % pairs_per_line == 0 ? '\n' : ':';
  }
  *p = '\0';
  return true;
}
