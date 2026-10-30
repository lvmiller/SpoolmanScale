#pragma once

#include <Arduino.h>
#include <string.h>

#include "filament_db.h"

// ============================================================
//  READING A FILAMENT DATABASE ANSWER WITH A BOUNDED BUDGET
//
//  WHOLE_DB covers only the Spoolman-form whole database: 3 MB measured at
//  11.5 s in filament_db_store.h. ANSWER covers every other catalog answer
//  on either task. The three loaders (spoolman_filament_db.cpp,
//  filaman_filament_db.cpp, bambuddy_filament_db.cpp) and fdb_json.cpp read
//  through this class, in blocks rather than one socket read per byte.
//  One answer stops at max_bytes, no later than max_ms plus one request
//  per-read timeout: SM_FDB_TIMEOUT_MS 15 s, SM_FIL_DB_TIMEOUT_MS 12 s,
//  SM_FIL_TIMEOUT_MS 8 s, FM_FDB_TIMEOUT_MS 20 s, BB_FDB_TIMEOUT_MS 15 s.
//  The BamBuddy colour-name lookup keeps its caller's timeout (default 6 s).
// ============================================================

#define FDB_READ_BUF  1024

struct FdbReadLimit {
  uint32_t max_ms;     // from the reader's start, absolute
  size_t   max_bytes;  // hard cap on the body bytes handed on
};
#define FDB_WHOLE_DB_MAX_MS     120000UL
#define FDB_WHOLE_DB_MAX_BYTES  (8UL * 1024UL * 1024UL)
#define FDB_ANSWER_MAX_MS       15000UL
#define FDB_ANSWER_MAX_BYTES    (2UL * 1024UL * 1024UL)
constexpr FdbReadLimit FDB_LIMIT_WHOLE_DB = { FDB_WHOLE_DB_MAX_MS, FDB_WHOLE_DB_MAX_BYTES };
constexpr FdbReadLimit FDB_LIMIT_ANSWER   = { FDB_ANSWER_MAX_MS, FDB_ANSWER_MAX_BYTES };

// Hands the body on in blocks, never asking the socket for more than it
// already has: on a kept connection a read past the end of the answer would
// wait out the timeout. Counts what it read for the waiting card.
class FdbBlockStream : public Stream {
 public:
  FdbBlockStream(Stream& in, const FdbReadLimit& limit)
      : in_(in), limit_(limit), start_ms_((uint32_t)millis()) {}
  bool exhausted() const { return exhausted_; }
  size_t bytesRead() const { return read_; }
  int available() override { return (int)(len_ - pos_) + in_.available(); }
  int read() override { return fill() ? buf_[pos_++] : -1; }
  int peek() override { return fill() ? buf_[pos_] : -1; }
  size_t readBytes(char* out, size_t n) override {
    size_t got = 0;
    while (got < n && fill()) {
      size_t k = len_ - pos_;
      if (k > n - got) k = n - got;
      memcpy(out + got, buf_ + pos_, k);
      pos_ += k;
      got += k;
    }
    return got;
  }
  size_t write(uint8_t) override { return 0; }
  void   flush() override {}
 private:
  bool fill() {
    if (pos_ < len_) return true;
    if (exhausted_) return false;
    if (read_ >= limit_.max_bytes ||
        (uint32_t)((uint32_t)millis() - start_ms_) >= limit_.max_ms) {
      exhausted_ = true;
      return false;
    }
    const int ready = in_.available();
    size_t want = ready > 0 ? (ready < FDB_READ_BUF ? (size_t)ready : FDB_READ_BUF) : 1;
    if (want > limit_.max_bytes - read_) want = limit_.max_bytes - read_;
    len_ = in_.readBytes((char*)buf_, want);
    pos_ = 0;
    read_ += len_;
    *fdbBytesCounter() += len_;
    return len_ > 0;
  }
  Stream& in_;
  FdbReadLimit limit_;
  uint32_t start_ms_;
  size_t read_ = 0;
  bool exhausted_ = false;
  uint8_t buf_[FDB_READ_BUF];
  size_t  len_ = 0;
  size_t  pos_ = 0;
};
