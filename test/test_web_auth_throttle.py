"""Compile the production throttle and check the device-wide password budget."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "web/web_auth_throttle.h"
#include <cassert>
#include <cstdio>

int main() {
  // A. Fixed-clock enumeration cannot reach even the correct legacy PIN.
  {
    WebAuthThrottle t;
    for (unsigned i = 0; i < 10000; ++i) {
      char pw[5];
      snprintf(pw, sizeof(pw), "%04u", i);
      assert(webAuthCheck(t, pw, "9999", 1000) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
    }
    assert(webAuthRetryMs(t, 1000) == 300000);

    // B. A correct PIN is refused while locked and never refills the budget.
    assert(webAuthCheck(t, "9999", "9999", 1000 + 299999) == WEB_AUTH_LOCKED);
    assert(webAuthCheck(t, "9999", "9999", 1000 + 300000) == WEB_AUTH_OK);
    assert(webAuthCheck(t, "1234", "9999", 1000 + 300000) == WEB_AUTH_LOCKED);
  }
  // C. Missing credentials do not consume attempts.
  {
    WebAuthThrottle t;
    for (unsigned i = 0; i < 10; ++i)
      assert(webAuthCheck(t, nullptr, "9999", 0) == WEB_AUTH_ASK);
    for (unsigned i = 0; i < 5; ++i) {
      char pw[5];
      snprintf(pw, sizeof(pw), "%04u", i);
      assert(webAuthCheck(t, pw, "9999", 0) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
    }
  }
  // D. Polling and duplicate upload checks count once, not once per request.
  {
    WebAuthThrottle t;
    for (unsigned i = 0; i < 20; ++i)
      assert(webAuthCheck(t, "1111", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "2222", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "3333", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "4444", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "5555", "9999", 0) == WEB_AUTH_LOCKED);
  }
  {
    WebAuthThrottle t;
    const char *pw[] = {"1111", "2222", "1111", "2222", "1111"};
    for (unsigned i = 0; i < 5; ++i)
      assert(webAuthCheck(t, pw[i], "9999", 0) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
  }
  // E. Sustained one-per-second guessing gets only 5 + 287 attempts in 24 h.
  {
    WebAuthThrottle t;
    unsigned evaluated = 0;
    for (uint32_t s = 0; s < 86400; ++s) {
      const uint32_t now = s * 1000;
      char pw[7];
      snprintf(pw, sizeof(pw), "%06u", (unsigned)s);
      if (webAuthRetryMs(t, now) == 0) ++evaluated;
      assert(webAuthCheck(t, pw, "999999", now) != WEB_AUTH_OK);
    }
    assert(evaluated == 292);
  }
  // F. The deadline survives millis() wrapping through zero.
  {
    WebAuthThrottle t;
    const uint32_t now0 = 0xFFFFFF00u;
    for (unsigned i = 0; i < 5; ++i) {
      char pw[5];
      snprintf(pw, sizeof(pw), "%04u", i);
      assert(webAuthCheck(t, pw, "9999", now0) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
    }
    assert(webAuthRetryMs(t, now0 + 299999u) == 1);
    assert(webAuthRetryMs(t, now0 + 300000u) == 0);
  }
  // G. Partial refills keep their remainder, but cannot grow past five.
  {
    WebAuthThrottle t;
    for (unsigned i = 0; i < 5; ++i) {
      char pw[5];
      snprintf(pw, sizeof(pw), "%04u", i);
      assert(webAuthCheck(t, pw, "9999", 0) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
    }
    assert(webAuthRetryMs(t, 450000) == 0);
    assert(webAuthCheck(t, "1111", "9999", 450000) == WEB_AUTH_LOCKED);
    assert(webAuthRetryMs(t, 450000) == 150000);
    for (unsigned i = 0; i < 5; ++i) {
      char pw[5];
      snprintf(pw, sizeof(pw), "%04u", i);
      assert(webAuthCheck(t, pw, "9999", 1800000) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
    }
  }
  // H. Local recovery restores the budget and forgets the last wrong value.
  {
    WebAuthThrottle t;
    for (unsigned i = 0; i < 5; ++i) {
      char pw[5];
      snprintf(pw, sizeof(pw), "%04u", i);
      assert(webAuthCheck(t, pw, "9999", 0) ==
             (i < 4 ? WEB_AUTH_ASK : WEB_AUTH_LOCKED));
    }
    webAuthReset(t);
    assert(webAuthCheck(t, "9999", "9999", 0) == WEB_AUTH_OK);
    assert(webAuthCheck(t, "0004", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "1111", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "2222", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "3333", "9999", 0) == WEB_AUTH_ASK);
    assert(webAuthCheck(t, "4444", "9999", 0) == WEB_AUTH_LOCKED);
  }
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("web password throttle: ok")
