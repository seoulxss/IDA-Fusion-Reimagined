#pragma once

// IDA-Fusion signature engine (IDA 9.x)
//
// Everything in here works on a snapshot of the database bytes, so a search
// is a plain memory scan and signature generation never has to go through
// IDA's (slow) per-call binary search.

#include <cstdint>
#include <string>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <ua.hpp>

namespace fusion {

// ida/code are signatures; the rest are hashes over the signature bytes where every
// wildcard is hashed as 0x00 (so the value stays the same between builds).
enum class style_t { ida, code, fnv1a, crc32, xxh32, xxh64, xxh128 };

inline bool is_hash(style_t s) { return s != style_t::ida && s != style_t::code; }
const char* style_name(style_t s);

struct options_t {
  bool wildcard_displ = true;   // wildcard 32 bit displacements ([reg+disp32])
  bool wildcard_imm   = false;  // wildcard every 32/64 bit immediate (offset operands are always wildcarded)
  size_t max_bytes    = 512;    // give up after this many bytes
};

// A byte pattern; fixed[i] == 0 means "any byte".
struct pattern_t {
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> fixed;

  size_t size() const { return bytes.size(); }
  bool empty() const  { return bytes.empty(); }
  void add(uint8_t b, bool is_fixed) { bytes.push_back(b); fixed.push_back(is_fixed ? 1 : 0); }
  void trim();  // remove wildcards at the front and at the back
};

std::string format(const pattern_t& pat, style_t style);

// Accepts IDA style ("48 8B ? ? 05", "48 8B ?? ?? 05") and CODE style
// ("\x48\x8B\x00\x00\x05", optionally followed by a mask like "xx??x").
// Without a mask, a CODE style \x00 is treated as a wildcard.
bool parse(const char* text, pattern_t& out, std::string& error);

// Snapshot of all loaded segments.
class image_t {
public:
  struct blob_t {
    ea_t start = 0;
    std::vector<uint8_t> data;
  };

  // Returns false when cancelled by the user.
  bool capture();

  // Adds bytes by hand (used by capture() and by the tests).
  void add_blob(ea_t start, std::vector<uint8_t> data);

  // Every address the pattern matches at. Stops after `limit` hits.
  std::vector<ea_t> find(const pattern_t& pat, size_t limit = SIZE_MAX) const;

  // Pointer to `len` bytes at `ea`, or nullptr if the range is not inside one segment.
  const uint8_t* at(ea_t ea, size_t len) const;

  size_t total_bytes() const;

private:
  std::vector<blob_t> blobs_;
};

struct generated_t {
  pattern_t pattern;
  size_t    other_matches = 0;      // matches besides the source address
  bool      unique        = false;
  size_t    insn_count    = 0;
  std::string note;                 // why generation stopped, if not unique
};

// Signature for the code starting at `start`, extended instruction by
// instruction until it matches nowhere else.
bool generate(const image_t& image, ea_t start, const options_t& opt, generated_t& out);

// Signature for exactly the instructions in [start, end).
bool generate_range(const image_t& image, ea_t start, ea_t end, const options_t& opt, generated_t& out);

bool copy_to_clipboard(const std::string& text);

}  // namespace fusion
