#include "fusion.h"

#include <algorithm>
#include <cctype>
#include <cstring>

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

std::string format(const pattern_t& pat, style_t style) {
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

  std::string s = text ? text : "";
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

void image_t::add_blob(ea_t start, std::vector<uint8_t> data) {
  blob_t blob;
  blob.start = start;
  blob.data  = std::move(data);
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

std::vector<ea_t> image_t::find(const pattern_t& pat, size_t limit) const {
  std::vector<ea_t> hits;

  // Anchor on the first fixed byte so memchr can do the heavy lifting
  size_t anchor = 0;
  while (anchor < pat.size() && !pat.fixed[anchor])
    ++anchor;
  if (anchor >= pat.size())
    return hits;

  const uint8_t key = pat.bytes[anchor];

  for (const blob_t& b : blobs_) {
    if (b.data.size() < pat.size())
      continue;

    const uint8_t* base = b.data.data();
    const uint8_t* last = base + (b.data.size() - pat.size());  // last valid start
    const uint8_t* p    = base + anchor;

    while (p <= last + anchor) {
      p = (const uint8_t*)memchr(p, key, (size_t)(last + anchor - p) + 1);
      if (!p)
        break;

      const uint8_t* start = p - anchor;
      if (match_at(start, pat)) {
        hits.push_back(b.start + (ea_t)(start - base));
        if (hits.size() >= limit)
          return hits;
      }
      ++p;
    }
  }

  return hits;
}

}  // namespace fusion
