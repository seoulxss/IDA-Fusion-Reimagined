// Logic tests for the parts of the engine that do not need a running IDA.
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

  printf(failures ? "%d FAILED\n" : "all tests passed\n", failures);
  return failures != 0;
}
