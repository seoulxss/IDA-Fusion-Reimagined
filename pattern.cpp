#include "fusion.h"

#include <algorithm>
#include <cctype>
#include <atomic>
#include <cstring>
#include <thread>

#define XXH_INLINE_ALL
#include "third_party/xxhash/xxhash.h"

// Pattern parsing / formatting and the memory scanner. Nothing in here calls into IDA.

namespace fusion {

// ---------------------------------------------------------------------------
// pattern
// ---------------------------------------------------------------------------

void pattern_t::trim() {
  while (!fixed.empty() && !fixed.back()) {
    bytes.pop_back();
    fixed.pop_back();
  }

  size_t lead = 0;
  while (lead < fixed.size() && !fixed[lead])
    ++lead;

  if (lead) {
    bytes.erase(bytes.begin(), bytes.begin() + lead);
    fixed.erase(fixed.begin(), fixed.begin() + lead);
  }
}

const char* style_name(style_t s) {
  switch (s) {
    case style_t::ida:    return "IDA";
    case style_t::code:   return "CODE";
    case style_t::fnv1a:  return "FNV-1a";
    case style_t::crc32:  return "CRC-32";
    case style_t::xxh32:  return "XXH32";
    case style_t::xxh64:  return "XXH64";
    case style_t::xxh128: return "XXH128";
  }
  return "?";
}

static uint32_t fnv1a_32(const uint8_t* p, size_t n) {
  uint32_t h = 0x811C9DC5u;
  for (size_t i = 0; i < n; ++i)
    h = (h ^ p[i]) * 0x01000193u;
  return h;
}

static uint32_t crc32_ieee(const uint8_t* p, size_t n) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; ++i) {
    crc ^= p[i];
    for (int k = 0; k < 8; ++k)
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}

static void append_hex(std::string& out, uint64_t v, int digits) {
  static const char hex[] = "0123456789ABCDEF";
  for (int i = digits - 1; i >= 0; --i)
    out += hex[(v >> (i * 4)) & 0xF];
}

static std::string format_hash(const pattern_t& pat, style_t style) {
  // Wildcards are hashed as 0x00
  std::vector<uint8_t> data(pat.size());
  for (size_t i = 0; i < pat.size(); ++i)
    data[i] = pat.fixed[i] ? pat.bytes[i] : 0;

  const uint8_t* p = data.data();
  const size_t   n = data.size();
  std::string    out = "0x";

  switch (style) {
    case style_t::fnv1a:  append_hex(out, fnv1a_32(p, n), 8); break;
    case style_t::crc32:  append_hex(out, crc32_ieee(p, n), 8); break;
    case style_t::xxh32:  append_hex(out, XXH32(p, n, 0), 8); break;
    case style_t::xxh64:  append_hex(out, XXH64(p, n, 0), 16); break;
    case style_t::xxh128: {
      XXH128_hash_t h = XXH3_128bits(p, n);
      append_hex(out, h.high64, 16);
      append_hex(out, h.low64, 16);
      break;
    }
    default:
      return std::string();
  }
  return out;
}

std::string format(const pattern_t& pat, style_t style) {
  if (is_hash(style))
    return format_hash(pat, style);

  static const char hex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(pat.size() * 4);

  for (size_t i = 0; i < pat.size(); ++i) {
    if (style == style_t::ida) {
      if (i)
        out += ' ';
      if (pat.fixed[i]) {
        out += hex[pat.bytes[i] >> 4];
        out += hex[pat.bytes[i] & 0xF];
      } else {
        out += '?';
      }
    } else {
      out += "\\x";
      if (pat.fixed[i]) {
        out += hex[pat.bytes[i] >> 4];
        out += hex[pat.bytes[i] & 0xF];
      } else {
        out += "00";
      }
    }
  }
  return out;
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parse(const char* text, pattern_t& out, std::string& error) {
  out = pattern_t();
  error.clear();

  // Tolerate how signatures get pasted around: quotes (python b"..."), braces and
  // semicolons (C arrays and strings)
  std::string s;
  {
    const std::string raw = text ? text : "";
    for (size_t k = 0; k < raw.size(); ++k) {
      const char c = raw[k];
      if (c == '"' || c == '\'' || c == '{' || c == '}' || c == ';')
        continue;
      const bool bytes_prefix = c == 'b' && k + 1 < raw.size() && (raw[k + 1] == '"' || raw[k + 1] == '\'') &&
                                (k == 0 || !std::isalnum((unsigned char)raw[k - 1]));
      if (bytes_prefix)
        continue;
      s += c;
    }
  }
  const bool code_style = s.find("\\x") != std::string::npos;

  if (code_style) {
    size_t i = 0;
    auto skip_ws = [&] { while (i < s.size() && std::isspace((unsigned char)s[i])) ++i; };

    skip_ws();
    while (i + 3 < s.size() + 0 && s[i] == '\\' && s[i + 1] == 'x') {
      int hi = hex_value(s[i + 2]);
      int lo = hex_value(s[i + 3]);
      if (hi < 0 || lo < 0) {
        error = "invalid \\x escape";
        return false;
      }
      uint8_t b = (uint8_t)(hi << 4 | lo);
      out.add(b, true);
      i += 4;
      skip_ws();
    }

    // Optional mask ("xx??x") after the bytes
    std::string mask = s.substr(i);
    if (!mask.empty()) {
      if (mask.size() != out.size()) {
        error = "mask length does not match the number of bytes";
        return false;
      }
      for (size_t k = 0; k < mask.size(); ++k) {
        char m = mask[k];
        if (m == 'x' || m == 'X') out.fixed[k] = 1;
        else if (m == '?' || m == '.') out.fixed[k] = 0;
        else {
          error = "mask may only contain 'x' and '?'";
          return false;
        }
      }
    } else {
      // No mask: a zero byte is the wildcard marker of CODE style signatures
      for (size_t k = 0; k < out.size(); ++k)
        out.fixed[k] = out.bytes[k] != 0;
    }
  } else {
    size_t i = 0;
    while (i < s.size()) {
      while (i < s.size() && (std::isspace((unsigned char)s[i]) || s[i] == ','))
        ++i;
      if (i >= s.size())
        break;

      size_t j = i;
      while (j < s.size() && !std::isspace((unsigned char)s[j]) && s[j] != ',')
        ++j;

      std::string tok = s.substr(i, j - i);
      i = j;

      if (tok == "?" || tok == "??" || tok == "*" || tok == "**") {
        out.add(0, false);
        continue;
      }

      if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X'))
        tok.erase(0, 2);

      // Run of hex digits without separators: "48895C24"
      if (tok.size() > 2 && tok.size() % 2 == 0) {
        bool all_hex = true;
        for (char c : tok)
          all_hex &= hex_value(c) >= 0;
        if (all_hex) {
          for (size_t k = 0; k < tok.size(); k += 2)
            out.add((uint8_t)(hex_value(tok[k]) << 4 | hex_value(tok[k + 1])), true);
          continue;
        }
      }

      if (tok.empty() || tok.size() > 2) {
        error = "invalid token '" + tok + "'";
        return false;
      }

      int v = 0;
      for (char c : tok) {
        int h = hex_value(c);
        if (h < 0) {
          error = "invalid token '" + tok + "'";
          return false;
        }
        v = v << 4 | h;
      }
      out.add((uint8_t)v, true);
    }
  }

  if (out.empty()) {
    error = "empty signature";
    return false;
  }

  bool any_fixed = false;
  for (uint8_t f : out.fixed)
    any_fixed |= f != 0;
  if (!any_fixed) {
    error = "signature consists only of wildcards";
    return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// image
// ---------------------------------------------------------------------------

void image_t::add_blob(ea_t start, std::vector<uint8_t> data, bool executable) {
  blob_t blob;
  blob.start      = start;
  blob.data       = std::move(data);
  blob.executable = executable;
  blobs_.push_back(std::move(blob));
}

size_t image_t::total_bytes() const {
  size_t total = 0;
  for (const blob_t& b : blobs_)
    total += b.data.size();
  return total;
}

const uint8_t* image_t::at(ea_t ea, size_t len) const {
  for (const blob_t& b : blobs_) {
    if (ea >= b.start && ea - b.start < b.data.size()) {
      size_t off = (size_t)(ea - b.start);
      return (b.data.size() - off >= len) ? b.data.data() + off : nullptr;
    }
  }
  return nullptr;
}

static bool match_at(const uint8_t* p, const pattern_t& pat) {
  for (size_t i = 0; i < pat.size(); ++i)
    if (pat.fixed[i] && p[i] != pat.bytes[i])
      return false;
  return true;
}

// Bytes that show up all over x86 code and padding, most common first. memchr stops at every
// occurrence of its key, so anchoring on a byte that is not in this list means far fewer stops.
static int commonness(uint8_t b) {
  static const uint8_t common[] = {0x00, 0xCC, 0xFF, 0x48, 0x8B, 0x89, 0x24, 0x0F, 0x83, 0x01, 0x04, 0x08, 0x10,
                                   0xE8, 0x45, 0x4C, 0x20, 0x40, 0x41, 0xC0, 0x05, 0x90, 0x5C, 0x8D, 0xC7};
  for (size_t i = 0; i < sizeof(common); ++i)
    if (common[i] == b)
      return (int)(sizeof(common) - i);  // larger = more common
  return 0;
}

// Matches that start in [begin, end) of one blob, ascending.
static void scan_range(const image_t::blob_t& b, const pattern_t& pat, size_t anchor, size_t begin, size_t end,
                       size_t limit, std::vector<ea_t>& out) {
  if (begin >= end)
    return;

  const uint8_t  key  = pat.bytes[anchor];
  const uint8_t* base = b.data.data();
  const uint8_t* p    = base + begin + anchor;
  const uint8_t* stop = base + end + anchor;  // one past the last anchor position

  while (p < stop) {
    p = (const uint8_t*)memchr(p, key, (size_t)(stop - p));
    if (!p)
      break;

    const uint8_t* start = p - anchor;
    if (match_at(start, pat)) {
      out.push_back(b.start + (ea_t)(start - base));
      if (out.size() >= limit)
        return;
    }
    ++p;
  }
}

std::vector<ea_t> image_t::find(const pattern_t& pat, size_t limit, bool code_only) const {
  std::vector<ea_t> hits;

  // Anchor on the least common fixed byte
  size_t anchor = pat.size();
  int    best   = INT32_MAX;
  for (size_t i = 0; i < pat.size(); ++i) {
    if (!pat.fixed[i])
      continue;
    int c = commonness(pat.bytes[i]);
    if (c < best) {
      best   = c;
      anchor = i;
    }
  }
  if (anchor >= pat.size())
    return hits;

  struct task_t { const blob_t* blob; size_t begin, end; };
  std::vector<task_t> tasks;
  size_t              scanned = 0;
  constexpr size_t    task_size = 4u << 20;

  for (const blob_t& b : blobs_) {
    if ((code_only && !b.executable) || b.data.size() < pat.size())
      continue;
    const size_t starts = b.data.size() - pat.size() + 1;  // possible match positions
    for (size_t off = 0; off < starts; off += task_size)
      tasks.push_back({&b, off, std::min(off + task_size, starts)});
    scanned += starts;
  }

  unsigned workers = std::thread::hardware_concurrency();
  workers          = std::min<unsigned>(workers ? workers : 1, 16);

  // Small images and limited searches are not worth threads (and a limit wants the first hits)
  if (limit != SIZE_MAX || scanned < (8u << 20) || workers < 2) {
    for (const task_t& t : tasks) {
      scan_range(*t.blob, pat, anchor, t.begin, t.end, limit, hits);
      if (hits.size() >= limit)
        break;
    }
    return hits;
  }

  std::vector<std::vector<ea_t>> parts(tasks.size());
  std::atomic<size_t>            next{0};
  auto worker = [&] {
    for (size_t i; (i = next.fetch_add(1)) < tasks.size();)
      scan_range(*tasks[i].blob, pat, anchor, tasks[i].begin, tasks[i].end, SIZE_MAX, parts[i]);
  };

  std::vector<std::thread> pool;
  for (unsigned i = 1; i < workers; ++i)
    pool.emplace_back(worker);
  worker();
  for (std::thread& t : pool)
    t.join();

  for (std::vector<ea_t>& part : parts)
    hits.insert(hits.end(), part.begin(), part.end());
  std::sort(hits.begin(), hits.end());
  return hits;
}

}  // namespace fusion
