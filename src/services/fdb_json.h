#pragma once

#include <ArduinoJson.h>

#include "fdb_block_stream.h"

// One catalog answer parsed whole into doc, through filter when there is one,
// read within limit. For spoolmanGetStreamed(), filamanGetStreamed() and
// bbGetStreamed(), which all take this reader.
struct FdbJsonRead {
  JsonDocument*       doc;
  JsonDocument*       filter;   // nullptr: the whole answer is kept
  const FdbReadLimit* limit;
  const char*         what;     // names the answer in the log
};
bool fdbReadJson(Stream& body, void* read);
