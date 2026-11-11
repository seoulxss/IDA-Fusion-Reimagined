// Copyright 2026 seoulxss
// Licensed under the Apache License, Version 2.0, see LICENSE and NOTICE.
// Based on IDA-Fusion by senator715 (Apache-2.0); substantially modified, see the git history.

// Logic tests for the parts of the engine that do not need a running IDA.
#include "../dialog_form.h"
#include "../fusion.h"
#include <cstdio>

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

int main() {
  using namespace fusion;
  pattern_t p; std::string err;

  CHECK(parse("48 8B ? ? 05", p, err));
  CHECK(p.size() == 5 && p.fixed[2] == 0 && p.fixed[3] == 0 && p.bytes[4] == 0x05);
  CHECK(format(p, style_t::ida) == "48 8B ? ? 05");
  CHECK(format(p, style_t::code) == "\\x48\\x8B\\x00\\x00\\x05");

  CHECK(parse("\\x48\\x8B\\x00\\x00\\x05", p, err));
  CHECK(p.size() == 5 && p.fixed[2] == 0 && p.fixed[4] == 1);
  CHECK(parse("\\x48\\x00\\x05 x?x", p, err) && p.fixed[1] == 0);
  CHECK(parse("\\x48\\x00\\x05 xxx", p, err) && p.fixed[1] == 1);   // explicit mask keeps a real 00
  CHECK(!parse("\\x48\\x00\\x05 xx", p, err));
  CHECK(parse("0x48 0x8b ??", p, err) && p.size() == 3);
  CHECK(!parse("", p, err));
  CHECK(!parse("? ? ?", p, err));
  CHECK(!parse("48 ZZ", p, err));
  CHECK(!parse("48 123", p, err));

  // extra notations accepted by the search
  CHECK(parse("48895C24", p, err) && p.size() == 4 && p.bytes[2] == 0x5C);
  CHECK(parse("{ 0x48, 0x89, 0x5C, 0x24 };", p, err) && p.size() == 4 && p.bytes[3] == 0x24);
  CHECK(parse("b\"\\x48\\x89\\x00\"", p, err) && p.size() == 3 && p.fixed[2] == 0);
  CHECK(parse("48 89 ?? ?? 24", p, err) && p.size() == 5 && p.fixed[2] == 0);
  CHECK(!parse("48895", p, err));   // odd run of digits

  // search
  std::vector<uint8_t> mem(4096, 0x90);
  mem[100] = 0x48; mem[101] = 0x8B; mem[102] = 0x11; mem[103] = 0x22; mem[104] = 0x05;
  mem[2000] = 0x48; mem[2001] = 0x8B; mem[2002] = 0x77; mem[2003] = 0x66; mem[2004] = 0x05;
  mem[4094] = 0x48; mem[4095] = 0x8B;                      // incomplete at the end: no match
  image_t img;
  img.add_blob(0x140001000, mem);
  parse("48 8B ? ? 05", p, err);
  auto hits = img.find(p);
  CHECK(hits.size() == 2 && hits[0] == 0x140001000 + 100 && hits[1] == 0x140001000 + 2000);
  CHECK(img.find(p, 1).size() == 1);

  parse("? 8B 11", p, err);                                 // leading wildcard
  hits = img.find(p);
  CHECK(hits.size() == 1 && hits[0] == 0x140001000 + 100);

  parse("48 8B 99", p, err);
  CHECK(img.find(p).empty());

  CHECK(img.at(0x140001000 + 4090, 6) != nullptr);
  CHECK(img.at(0x140001000 + 4090, 7) == nullptr);
  CHECK(img.at(0x1000, 1) == nullptr);

  pattern_t t; t.add(0, false); t.add(1, true); t.add(0, false);
  t.trim();
  CHECK(t.size() == 1 && t.bytes[0] == 1);

  // immediates are wildcarded by default (syscall IDs shift between builds), displacements too
  CHECK(options_t().wildcard_imm && options_t().wildcard_displ);

  // output options
  {
    options_t o;
    pattern_t a, z;
    parse("48 8B ? ? 05", a, err);
    CHECK(format(a, style_t::ida, o) == "48 8B ? ? 05");
    o.double_question = true;
    CHECK(format(a, style_t::ida, o) == "48 8B ?? ?? 05");
    o = options_t();
    CHECK(format(a, style_t::code, o) == "\\x48\\x8B\\x00\\x00\\x05");   // no real 00: no mask needed
    o.code_mask = true;
    CHECK(format(a, style_t::code, o) == "\\x48\\x8B\\x00\\x00\\x05 xx??x");

    // a real zero byte would read back as a wildcard, so the mask is added on its own
    parse("48 00 05 ? 90", z, err);
    CHECK(z.fixed[1] == 1);
    o = options_t();
    const std::string zc = format(z, style_t::code, o);
    CHECK(zc == "\\x48\\x00\\x05\\x00\\x90 x?x?x" || zc == "\\x48\\x00\\x05\\x00\\x90 xxx?x");
    pattern_t back;
    CHECK(parse(zc.c_str(), back, err));
    CHECK(back.fixed == z.fixed);                                       // the real 00 survived the round trip
  }

  // the paste-ready C++ line of the XREF output
  CHECK(cpp_resolve_line(1, 5) ==
        "const std::uintptr_t target = match + 5 + static_cast<std::uintptr_t>(*reinterpret_cast<const std::int32_t*>(match + 1));");
  CHECK(cpp_resolve_line(2, 6).find("match + 6 + ") != std::string::npos &&
        cpp_resolve_line(2, 6).find("(match + 2)") != std::string::npos);
  CHECK(cpp_resolve_line(1, 5).find("(std::") == std::string::npos);     // no C style cast like (std::int32_t)
  // the width of the displacement follows the instruction: short jumps have one byte, never read four
  CHECK(cpp_resolve_line(1, 2).find("std::int8_t") != std::string::npos);
  CHECK(cpp_resolve_line(1, 2).find("std::int32_t") == std::string::npos);
  CHECK(cpp_resolve_line(2, 6).find("std::int32_t") != std::string::npos);   // 0F 8x near conditional jump
  CHECK(cpp_resolve_line(1, 3).empty());                                     // 16 bit displacement: not guessed
  CHECK(cpp_resolve_line(5, 5).empty());

  // hashes: published check values for "123456789"
  parse("31 32 33 34 35 36 37 38 39", p, err);
  CHECK(format(p, style_t::fnv1a) == "0xBB86B11C");
  CHECK(format(p, style_t::crc32) == "0xCBF43926");
  CHECK(format(p, style_t::xxh32) == "0x937BAD67");
  CHECK(format(p, style_t::xxh64) == "0x8CB841DB40E6AE83");
  CHECK(format(p, style_t::xxh128).size() == 34 && format(p, style_t::xxh128).rfind("0x", 0) == 0);
  // wildcards are hashed as 00
  pattern_t w, z;
  parse("31 ? 33 ? 35", w, err);
  parse("31 00 33 00 35", z, err);   // IDA style: 00 here is a real zero byte
  for (style_t st : {style_t::fnv1a, style_t::crc32, style_t::xxh32, style_t::xxh64, style_t::xxh128})
    CHECK(format(w, st) == format(z, st));
  // the real byte behind a wildcard must not leak into the hash
  pattern_t w2 = w; w2.bytes[1] = 0xAA;
  CHECK(format(w, style_t::xxh64) == format(w2, style_t::xxh64));

  // The dialog string: ask_form() refuses a malformed one silently, so check what is known to break it.
  {
    const std::string form = fusion::DIALOG_FORM;
    size_t items = 0, radios = 0, checks = 0;
    for (size_t i = 0; (i = form.find('<', i)) != std::string::npos;) {
      size_t end = form.find('>', i);
      CHECK(end != std::string::npos);
      std::string item = form.substr(i + 1, end - i - 1);   // label:type
      size_t colon = item.rfind(':');
      CHECK(colon != std::string::npos);
      std::string label = item.substr(0, colon), type = item.substr(colon + 1);
      CHECK(label.find(':') == std::string::npos);          // ':' separates label and type
      CHECK(label.find('#') == std::string::npos);          // '#' delimits hints
      CHECK(label.find('<') == std::string::npos && label.find('>') == std::string::npos);
      CHECK(type == "R" || type == "C");
      radios += type == "R";
      checks += type == "C";
      ++items;
      i = end + 1;
    }
    CHECK(items == 16 && radios == 3 && checks == 13);
    CHECK(fusion::DIALOG_OUTPUT_COUNT == 7 && fusion::DIALOG_OPTION_COUNT == 6);
    // the layout that crashed IDA 9.5: a form-change callback together with a third button
    CHECK(form.find("%/") == std::string::npos);
    CHECK(form.find("BUTTON NO") == std::string::npos);
    // one closed group per type: the last item of each group is followed by a second '>'
    size_t closers = 0;
    for (size_t i = 0; (i = form.find(">>", i)) != std::string::npos; i += 2)
      ++closers;
    CHECK(closers == 3);
  }

  // Large image: scanned by several threads. Plant matches right at the 4 MB task borders.
  {
    const size_t   mb = 1u << 20;
    std::vector<uint8_t> big(24 * mb, 0xCC);
    // none of them overlap; two straddle a task border, one starts exactly on one
    std::vector<size_t> planted = {0, 4 * mb - 3, 4 * mb + 2, 8 * mb - 2, 12 * mb, 16 * mb + 7, 24 * mb - 5};
    for (size_t at : planted) {
      const uint8_t sig[5] = {0x48, 0x8B, 0xAA, 0xBB, 0x05};
      for (int k = 0; k < 5; ++k) big[at + k] = sig[k];
    }
    image_t large;
    large.add_blob(0x140000000, big);
    parse("48 8B ? ? 05", p, err);

    auto par = large.find(p);                       // threaded
    CHECK(par.size() == planted.size());
    for (size_t k = 0; k < par.size() && k < planted.size(); ++k)
      CHECK(par[k] == 0x140000000 + planted[k]);    // ascending, nothing doubled at the borders

    auto lim = large.find(p, 3);                    // sequential, with limit
    CHECK(lim.size() == 3 && lim[2] == 0x140000000 + planted[2]);

    // anchor on a rare byte, wildcards in front: "? ? AA BB 05" starts 2 before the signature
    parse("? ? ? AA BB 05", p, err);
    auto lead = large.find(p);
    size_t expect = 0;
    for (size_t at : planted) expect += at >= 3;    // the one at 0 has no room for 3 leading bytes
    CHECK(lead.size() == expect);
  }

  // code_only skips data segments
  {
    image_t two;
    std::vector<uint8_t> code(64, 0x90), data(64, 0x90);
    code[10] = 0x11; code[11] = 0x22; code[12] = 0x33;
    data[20] = 0x11; data[21] = 0x22; data[22] = 0x33;
    two.add_blob(0x1000, code, true);
    two.add_blob(0x2000, data, false);
    parse("11 22 33", p, err);
    CHECK(two.find(p).size() == 2);
    auto only = two.find(p, SIZE_MAX, true);
    CHECK(only.size() == 1 && only[0] == 0x100A);
  }

  printf(failures ? "%d FAILED\n" : "all tests passed\n", failures);
  return failures != 0;
}
