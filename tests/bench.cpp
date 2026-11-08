// Scan benchmark (no IDA needed):  bench <file> [copies]
// Loads a real binary, repeats it to get a large "database" and times a few patterns.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>

#include "../fusion.h"

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  std::ifstream f(argv[1], std::ios::binary);
  std::vector<uint8_t> one((std::istreambuf_iterator<char>(f)), {});
  const int copies = argc > 2 ? atoi(argv[2]) : 8;

  std::vector<uint8_t> data;
  data.reserve(one.size() * copies);
  for (int i = 0; i < copies; ++i) data.insert(data.end(), one.begin(), one.end());

  using clock = std::chrono::steady_clock;
  auto t0 = clock::now();
  fusion::image_t img;
  img.add_blob(0x140000000, std::move(data));
  auto t1 = clock::now();
  printf("image: %zu MB, add_blob %lld ms\n", img.total_bytes() >> 20,
         (long long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

  const char* pats[] = {
      "48 8B ? ? 05",                      // starts with a very common byte
      "48 89 5C 24 08 48 89 74 24 10 57",  // typical function prologue
      "CC CC CC CC CC CC CC CC",           // padding, extremely common
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41",
      "E8 ? ? ? ? 48 8B D8 48 85 C0",      // wildcards inside, anchor at the front
      "? ? ? 48 8D 05 ? ? ? ? 48 89",      // leading wildcards
  };
  for (const char* p : pats) {
    fusion::pattern_t pat; std::string err;
    if (!fusion::parse(p, pat, err)) { printf("bad %s\n", p); continue; }
    auto a = clock::now();
    size_t n = img.find(pat).size();
    auto b = clock::now();
    printf("%-52s %9zu hits %6lld ms\n", p, n, (long long)std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
  }
  return 0;
}
