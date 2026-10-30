#pragma once

#include <esp_tls.h>
#include <stddef.h>
#include <stdint.h>

// Loads key + certificate from NVS, or creates them; renews before expiry.
// True while an identity is in RAM. Cheap after the first success.
bool webTlsIdentityEnsure();
// PEM pair and ticket context used by each HTTPS session. Null before success.
esp_tls_cfg_server_t *webTlsServerConfig();
// SHA-256 of certificate DER: upper-case pairs, ':' separators, or '\n' after
// pairs_per_line pairs (0 = one line). Requires len >= 96. Empty on failure.
bool webTlsFingerprint(char *out, size_t len, uint8_t pairs_per_line);
