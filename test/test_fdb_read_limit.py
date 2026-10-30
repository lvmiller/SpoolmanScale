"""Compile the production catalog stream and check byte and elapsed-time limits."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
arduino = r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
unsigned long millis();
class Stream {
 public:
  virtual ~Stream() {}
  virtual int available() = 0;
  virtual int read() = 0;
  virtual int peek() = 0;
  virtual size_t readBytes(char* buffer, size_t length) = 0;
  virtual size_t write(uint8_t) = 0;
  virtual void flush() = 0;
};
'''
source = r'''
#include "services/fdb_block_stream.h"
#include <cassert>
#include <cstring>

static uint32_t now_ms;
unsigned long millis() { return now_ms; }
volatile size_t* fdbBytesCounter() {
  static volatile size_t count = 0;
  return &count;
}

class Finite : public Stream {
 public:
  explicit Finite(const char* text) : text_(text), remaining_(strlen(text)) {}
  int available() override { return (int)remaining_; }
  int read() override {
    if (!remaining_) return -1;
    --remaining_;
    return (unsigned char)*text_++;
  }
  int peek() override { return remaining_ ? (unsigned char)*text_ : -1; }
  size_t readBytes(char* out, size_t n) override {
    if (n > remaining_) n = remaining_;
    memcpy(out, text_, n);
    text_ += n;
    remaining_ -= n;
    return n;
  }
  size_t write(uint8_t) override { return 0; }
  void flush() override {}
 private:
  const char* text_;
  size_t remaining_;
};

class Endless : public Stream {
 public:
  Endless(char fill, uint32_t step_ms) : fill_(fill), step_ms_(step_ms) {}
  int available() override { return 4096; }
  int read() override { return fill_; }
  int peek() override { return fill_; }
  size_t readBytes(char* out, size_t n) override {
    now_ms += step_ms_;
    memset(out, fill_, n);
    return n;
  }
  size_t write(uint8_t) override { return 0; }
  void flush() override {}
 private:
  char fill_;
  uint32_t step_ms_;
};

int main() {
  {
    now_ms = 0;
    Finite body("  [1,2]");
    FdbBlockStream s(body, FDB_LIMIT_ANSWER);
    for (char c : "  [1,2]") {
      if (c) assert(s.read() == c);
    }
    assert(s.read() == -1);
    assert(!s.exhausted());
    assert(s.bytesRead() == 7);
  }
  {
    now_ms = 0;
    Endless body(' ', 0);
    FdbBlockStream s(body, FdbReadLimit{100000, 65536});
    for (size_t i = 0; i < 65536; ++i) assert(s.read() == ' ');
    assert(s.read() == -1);
    assert(s.exhausted());
    assert(s.read() == -1);
    assert(s.peek() == -1);
  }
  {
    now_ms = 0;
    Endless body('x', 0);
    FdbBlockStream s(body, FdbReadLimit{100000, 5000});
    char buf[8192];
    assert(s.readBytes(buf, sizeof(buf)) == 5000);
    assert(s.readBytes(buf, sizeof(buf)) == 0);
    assert(s.exhausted());
  }
  {
    now_ms = 0;
    Endless body(' ', 10);
    FdbBlockStream s(body, FdbReadLimit{100, 1u << 30});
    while (s.read() != -1) {}
    assert(s.exhausted());
    assert(s.bytesRead() == 10 * FDB_READ_BUF);
    assert(now_ms == 100);
  }
  {
    now_ms = 0xFFFFFFC0;
    Endless body(' ', 32);
    FdbBlockStream s(body, FdbReadLimit{200, 1u << 30});
    while (s.read() != -1) {}
    assert(s.exhausted());
    assert(s.bytesRead() == 7 * FDB_READ_BUF);
  }
  {
    now_ms = 0;
    Finite body("  [1,2]");
    FdbBlockStream s(body, FdbReadLimit{100000, 7});
    for (char c : "  [1,2]") {
      if (c) assert(s.read() == c);
    }
  }
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    (Path(tmp) / "Arduino.h").write_text(arduino)
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", tmp, "-I", str(root / "src"), str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("catalog read limit: ok")
