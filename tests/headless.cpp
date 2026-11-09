// Copyright 2026 seoulxss
// Licensed under the Apache License, Version 2.0, see LICENSE and NOTICE.
// Based on IDA-Fusion by senator715 (Apache-2.0); substantially modified, see the git history.

// Headless check of the signature engine against a real database (idalib).
//   fusion_headless <binary> [max_functions]
//
// For every function start: generate a signature, then verify with an independent scan
// of the snapshot that a "unique" signature matches exactly the function start.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <pro.h>
#include <ida.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <idalib.hpp>
#include <loader.hpp>

#include "../fusion.h"

// Wildcard positions carry the original byte in the generator, so compare fixed bytes only
static bool same_pattern(const fusion::pattern_t& a, const fusion::pattern_t& b) {
  if (a.size() != b.size() || a.fixed != b.fixed)
    return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (a.fixed[i] && a.bytes[i] != b.bytes[i])
      return false;
  return true;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("usage: %s <binary> [max_functions]\n", argv[0]);
    return 2;
  }
  const size_t max_funcs = argc > 2 ? (size_t)atoi(argv[2]) : 500;

  if (init_library() != 0) {
    printf("init_library failed\n");
    return 2;
  }
  enable_console_messages(false);

  // "capture" as 3rd argument: only time reading the database, skip auto-analysis
  const bool capture_only = argc > 3 && std::string(argv[3]) == "capture";

  if (open_database(argv[1], !capture_only) != 0) {
    printf("open_database failed\n");
    return 2;
  }
  if (!capture_only)
    auto_wait();

  using clock = std::chrono::steady_clock;
  auto t0 = clock::now();

  fusion::image_t image;
  if (!image.capture()) {
    printf("capture failed\n");
    return 1;
  }
  auto t1 = clock::now();
  printf("snapshot: %zu bytes in %lld ms\n", image.total_bytes(),
         (long long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

  if (capture_only) {
    for (int round = 0; round < 3; ++round) {
      fusion::image_t again;
      auto a = clock::now();
      again.capture();
      auto b = clock::now();
      printf("capture round %d: %zu MB in %lld ms\n", round, again.total_bytes() >> 20,
             (long long)std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
    }
    close_database(false);
    return 0;
  }

  fusion::options_t opt;
  size_t total = 0, unique = 0, not_unique = 0, mismatches = 0, failed = 0, sum_len = 0;
  size_t longest = 0;

  const size_t qty = get_func_qty();
  for (size_t i = 0; i < qty && total < max_funcs; ++i) {
    func_t* f = getn_func(i);
    if (!f)
      continue;
    const ea_t start = f->start_ea;

    fusion::generated_t g;
    ++total;
    if (!fusion::generate(image, start, opt, g)) {
      ++failed;
      continue;
    }

    if (g.unique) {
      ++unique;
      sum_len += g.pattern.size();
      longest = std::max(longest, g.pattern.size());

      // Independent verification
      std::vector<ea_t> hits = image.find(g.pattern);
      if (hits.size() != 1 || hits[0] != start) {
        ++mismatches;
        printf("MISMATCH at 0x%llX: %zu hits, sig %s\n", (unsigned long long)start, hits.size(),
               fusion::format(g.pattern, fusion::style_t::ida).c_str());
      }

      // The textual form must round-trip through the parser
      fusion::pattern_t reparsed;
      std::string err;
      if (!fusion::parse(fusion::format(g.pattern, fusion::style_t::ida).c_str(), reparsed, err) ||
          !same_pattern(reparsed, g.pattern)) {
        ++mismatches;
        printf("ROUNDTRIP failure at 0x%llX\n", (unsigned long long)start);
      }
    } else {
      ++not_unique;
      if (not_unique <= 8)
        printf("not unique 0x%llX: %zu other, %zu bytes, %zu insns, note: %s | %s\n", (unsigned long long)start,
               g.other_matches, g.pattern.size(), g.insn_count, g.note.c_str(),
               fusion::format(g.pattern, fusion::style_t::ida).c_str());
    }
  }
  auto t2 = clock::now();

  printf("functions: %zu  unique: %zu  not unique: %zu  failed: %zu  mismatches: %zu\n", total, unique, not_unique, failed, mismatches);
  if (unique)
    printf("avg signature length: %.1f bytes, longest %zu\n", (double)sum_len / unique, longest);
  printf("generation: %lld ms\n", (long long)std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count());

  // XREF signatures: every call site of the first functions that have any
  {
    size_t short_jumps = 0, funcs_with_refs = 0, sites_total = 0, sites_unique = 0, xref_mismatches = 0, with_branch_info = 0;
    for (size_t i = 0; i < qty && funcs_with_refs < 100000; ++i) {
      func_t* f = getn_func(i);
      if (!f)
        continue;
      size_t data_refs = 0;
      std::vector<ea_t> sites = fusion::code_xrefs_to(f->start_ea, &data_refs);
      if (sites.empty())
        continue;
      ++funcs_with_refs;

      for (ea_t site : sites) {
        ++sites_total;
        fusion::generated_t g;
        if (!is_code(get_flags(site)) || !fusion::generate(image, site, opt, g) || !g.unique)
          continue;
        ++sites_unique;

        std::vector<ea_t> hits = image.find(g.pattern);
        if (hits.size() != 1 || hits[0] != site) {
          ++xref_mismatches;
          printf("XREF MISMATCH site 0x%llX: %zu hits\n", (unsigned long long)site, hits.size());
        }
        size_t rel = 0, len = 0;
        if (fusion::describe_branch(site, rel, len) && rel < len) {
          ++with_branch_info;
          // The documented formula: target = match + instruction size + int32 at (match + rel)
          const size_t width = len - rel;
          if (width == 1)
            ++short_jumps;
          const int64 disp     = width == 1 ? (int64)(int8)get_byte(site + rel) : (int64)(int32)get_dword(site + rel);
          const ea_t  resolved = site + len + (ea_t)disp;
          if (width != 1 && width != 4)
            printf("odd displacement width %zu at 0x%llX\n", width, (unsigned long long)site);
          if (resolved != f->start_ea) {
            ++xref_mismatches;
            printf("RESOLVE MISMATCH site 0x%llX: got 0x%llX, expected 0x%llX\n", (unsigned long long)site,
                   (unsigned long long)resolved, (unsigned long long)f->start_ea);
          }
        }
      }
    }
    printf("xref: %zu functions, %zu call sites, %zu unique, %zu mismatches, %zu with displacement info (%zu short jumps)\n", funcs_with_refs,
           sites_total, sites_unique, xref_mismatches, with_branch_info, short_jumps);
    mismatches += xref_mismatches;
  }

  // Sample output
  if (qty) {
    func_t* f = getn_func(qty / 2);
    fusion::generated_t g;
    if (f && fusion::generate(image, f->start_ea, opt, g))
      printf("sample 0x%llX: %s (%s)\n", (unsigned long long)f->start_ea,
             fusion::format(g.pattern, fusion::style_t::ida).c_str(), g.unique ? "unique" : "not unique");
  }

  close_database(false);
  return mismatches || failed ? 1 : 0;
}
