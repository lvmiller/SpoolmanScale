#include <Arduino.h>

#include "fdb_json.h"
#include "../hardware/sd_logger.h"

bool fdbReadJson(Stream& body, void* read) {
  FdbJsonRead* r = (FdbJsonRead*)read;
  FdbBlockStream s(body, *r->limit);
  const DeserializationError err = r->filter
      ? deserializeJson(*r->doc, s, DeserializationOption::Filter(*r->filter))
      : deserializeJson(*r->doc, s);
  if (s.exhausted()) {
    logSDf("Filament DB: %s cut off by the read limit after %u bytes", r->what, (unsigned)s.bytesRead());
  } else if (err) {
    logSDf("Filament DB: %s did not parse: %s", r->what, err.c_str());
  }
  return !err && !s.exhausted();
}
