// Copyright 2026 seoulxss
// Licensed under the Apache License, Version 2.0, see LICENSE and NOTICE.
// Based on IDA-Fusion by senator715 (Apache-2.0); substantially modified, see the git history.

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
  bool wildcard_imm   = true;   // wildcard every 32/64 bit immediate (offset operands are always wildcarded).
                                // On by default: a syscall stub's ID is an imm32 and the IDs shift between
                                // builds - kept fixed, 205 of 488 ntdll stub signatures (26100.7920) matched
                                // exactly one stub in 26100.9711, the wrong one
  bool code_only      = false;  // only look at executable segments (faster, but data is not searched)
  bool stay_in_function = true; // do not extend a signature past the end of its function
  size_t max_bytes    = 512;    // give up after this many bytes

  // Output format
  bool double_question = false; // IDA style: "??" instead of "?"
  bool code_mask       = false; // CODE style: always append the mask ("xx??x"); otherwise only when a real
                                // 00 byte is in the signature, because \x00 alone would read as a wildcard
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

std::string format(const pattern_t& pat, style_t style, const options_t& opt);
std::string format(const pattern_t& pat, style_t style);  // default options

// Accepts IDA style ("48 8B ? ? 05", "48 8B ?? ?? 05") and CODE style
// ("\x48\x8B\x00\x00\x05", optionally followed by a mask like "xx??x").
// Without a mask, a CODE style \x00 is treated as a wildcard.
bool parse(const char* text, pattern_t& out, std::string& error);

// Snapshot of the loaded segments. Segments are read lazily and kept, so a second search
// does not read the database again; the owner calls clear() when the database changes.
class image_t {
public:
  struct blob_t {
    ea_t start = 0;
    std::vector<uint8_t> data;
    bool executable = true;
  };

  // Reads the segments that are not in the snapshot yet (only executable ones with `code_only`).
  // Returns false when cancelled by the user; segments read so far are kept.
  bool capture(bool code_only = false);

  // Adds bytes by hand (used by capture() and by the tests).
  void add_blob(ea_t start, std::vector<uint8_t> data, bool executable = true);

  void clear() { blobs_.clear(); }

  // Every address the pattern matches at, in ascending order. Stops after `limit` hits.
  // Large snapshots are scanned by several threads (not with a limit).
  std::vector<ea_t> find(const pattern_t& pat, size_t limit = SIZE_MAX, bool code_only = false) const;

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

// Signature for exactly the instructions in [start, end). Nothing is trimmed: the user picked these bytes.
bool generate_range(const image_t& image, ea_t start, ea_t end, const options_t& opt, generated_t& out);

// Code references (calls and jumps, no plain fall-through) to `target`, sorted and without duplicates.
// `data_refs` (optional) receives the number of data references, e.g. a vtable entry.
std::vector<ea_t> code_xrefs_to(ea_t target, size_t* data_refs = nullptr);

// Where the relative target of the call/jump at `site` is encoded: offset of the rel32 and the length of the
// instruction. False if it is not a direct call/jump with an encoded displacement.
bool describe_branch(ea_t site, size_t& rel_offset, size_t& insn_size);

// One line of C++ that turns the address of a match (a std::uintptr_t named `match`) into the target of the
// call/jump: the displacement at `match + rel_offset` is relative to the end of the instruction.
// No C style casts; the address stays an integer, only the 32 bit read goes through a pointer.
std::string cpp_resolve_line(size_t rel_offset, size_t insn_size);

bool copy_to_clipboard(const std::string& text);

}  // namespace fusion
