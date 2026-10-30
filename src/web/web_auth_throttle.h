#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ============================================================
//  DEVICE-WIDE WEB PASSWORD BUDGET
//
//  Connections, addresses and Basic user names share one state, so changing
//  any of them cannot reset the attempt budget. An empty bucket refuses even
//  the correct PIN: checking it would leave an unlimited guessing oracle.
//  Repeated wrong passwords and successes neither count nor refill, so an
//  old polling tab counts once and an authenticated tab cannot help guesses.
//  At five initial tries and one per five minutes, exhaustive guessing takes
//  about 34.7 days for 10,000 four-digit PINs, or 9.5 years for 10^6 six-digit
//  PINs in the worst case. Saving on the device or rebooting resets the state.
// ============================================================

#define WEB_AUTH_BURST      5
#define WEB_AUTH_REFILL_MS  (5UL * 60UL * 1000UL)
#define WEB_AUTH_PW_MAX     63

enum WebAuthResult : uint8_t { WEB_AUTH_OK = 0, WEB_AUTH_ASK, WEB_AUTH_LOCKED };

struct WebAuthThrottle {
  uint8_t  tokens = WEB_AUTH_BURST;
  uint32_t since_ms = 0;
  bool     has_wrong = false;
  char     last_wrong[WEB_AUTH_PW_MAX + 1] = {};
};

static inline void webAuthRefill(WebAuthThrottle &t, uint32_t now_ms) {
  if (t.tokens >= WEB_AUTH_BURST) return;
  const uint32_t steps = (uint32_t)(now_ms - t.since_ms) / WEB_AUTH_REFILL_MS;
  if (steps == 0) return;
  const uint32_t tokens = (uint32_t)t.tokens + steps;
  t.tokens = tokens < WEB_AUTH_BURST ? (uint8_t)tokens : WEB_AUTH_BURST;
  t.since_ms += steps * WEB_AUTH_REFILL_MS;
}

inline void webAuthReset(WebAuthThrottle &t) {
  t.tokens = WEB_AUTH_BURST;
  t.since_ms = 0;
  t.has_wrong = false;
  t.last_wrong[0] = '\0';
}

// The caller supplies a non-empty stored password.
inline WebAuthResult webAuthCheck(WebAuthThrottle &t, const char *presented,
                                  const char *pass, uint32_t now_ms) {
  webAuthRefill(t, now_ms);
  if (t.tokens == 0) return WEB_AUTH_LOCKED;
  if (!presented) return WEB_AUTH_ASK;
  if (strcmp(presented, pass) == 0) return WEB_AUTH_OK;
  if (t.has_wrong && strlen(presented) <= WEB_AUTH_PW_MAX &&
      strcmp(presented, t.last_wrong) == 0) return WEB_AUTH_ASK;
  if (t.tokens == WEB_AUTH_BURST) t.since_ms = now_ms;
  --t.tokens;
  snprintf(t.last_wrong, sizeof t.last_wrong, "%s", presented);
  t.has_wrong = true;
  return t.tokens == 0 ? WEB_AUTH_LOCKED : WEB_AUTH_ASK;
}

inline uint32_t webAuthRetryMs(WebAuthThrottle &t, uint32_t now_ms) {
  webAuthRefill(t, now_ms);
  return t.tokens > 0 ? 0 : WEB_AUTH_REFILL_MS - (uint32_t)(now_ms - t.since_ms);
}
