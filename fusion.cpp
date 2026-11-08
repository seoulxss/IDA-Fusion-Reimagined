#include "fusion.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include <fixup.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <kernwin.hpp>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace fusion {

// ---------------------------------------------------------------------------
// image
// ---------------------------------------------------------------------------

bool image_t::capture(bool code_only) {
  constexpr size_t chunk = 1u << 20;

  const int qty = get_segm_qty();
  for (int n = 0; n < qty; ++n) {
    segment_info_t seg;
    if (!get_segment_info_by_num(&seg, n))
      continue;

    const uchar type = seg.get_type();
    if (type == SEG_XTRN || type == SEG_BSS || type == SEG_GRP || type == SEG_COMM || type == SEG_ABSSYM)
      continue;
    if (seg.end_ea <= seg.start_ea)
      continue;

    const bool executable = (seg.get_perm() & SEGPERM_EXEC) != 0 || type == SEG_CODE;
    if (code_only && !executable)
      continue;

    // Already in the snapshot?
    const size_t size = (size_t)(seg.end_ea - seg.start_ea);
    bool         have = false;
    for (const blob_t& b : blobs_)
      have |= b.start == seg.start_ea && b.data.size() == size;
    if (have)
      continue;

    std::vector<uint8_t> data(size, 0);

    for (size_t off = 0; off < data.size(); off += chunk) {
      if (user_cancelled())
        return false;

      size_t len = std::min(chunk, data.size() - off);
      get_bytes(data.data() + off, (ssize_t)len, seg.start_ea + off, GMB_READALL);
    }

    add_blob(seg.start_ea, std::move(data), executable);
  }

  return true;
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

// Marks the bytes of `insn` that are expected to change between builds.
static void instruction_mask(const insn_t& insn, const options_t& opt, std::vector<uint8_t>& fixed) {
  fixed.assign(insn.size, 1);
  const flags64_t flags = get_flags(insn.ea);

  for (int n = 0; n < UA_MAXOP; ++n) {
    const op_t& op = insn.ops[n];
    if (op.type == o_void)
      break;
    if (op.offb == 0 || op.offb >= insn.size)
      continue;

    // The operand ends where the next operand starts (or at the end of the instruction)
    size_t end = insn.size;
    for (int m = n + 1; m < UA_MAXOP; ++m) {
      const op_t& next = insn.ops[m];
      if (next.type == o_void)
        break;
      if (next.offb > op.offb) {
        end = next.offb;
        break;
      }
    }

    const size_t room = end - op.offb;
    size_t       wipe = 0;

    switch (op.type) {
      case o_near:
      case o_far:
        if (room >= 4) wipe = 4;  // rel32 -- rel8 jumps stay stable
        break;

      case o_mem:
        if (room >= 8 && get_dtype_size(op.dtype) == 8 && insn.size - op.offb == 8) wipe = 8;  // moffs64
        else if (room >= 4) wipe = 4;                                                          // abs32 / rip+disp32
        break;

      case o_displ:
        if (opt.wildcard_displ && room >= 4) wipe = 4;
        break;

      case o_imm:
        if (room >= 4 && (opt.wildcard_imm || is_off(flags, n))) {
          size_t sz = (size_t)get_dtype_size(op.dtype);
          wipe      = std::min(room, sz >= 8 ? (size_t)8 : (size_t)4);
        }
        break;

      default:
        break;
    }

    for (size_t k = 0; k < wipe; ++k)
      fixed[op.offb + k] = 0;
  }
}

static bool append_instruction(const insn_t& insn, const options_t& opt, pattern_t& pat) {
  std::vector<uint8_t> fixed;
  instruction_mask(insn, opt, fixed);

  for (size_t i = 0; i < insn.size; ++i)
    pat.add(get_byte(insn.ea + i), fixed[i] != 0);
  return true;
}

bool generate(const image_t& image, ea_t start, const options_t& opt, generated_t& out) {
  out = generated_t();

  std::vector<ea_t> candidates;  // addresses that still match the pattern (excluding `start`)
  bool              seeded = false;
  size_t            pending_from = 0;  // first pattern byte not yet verified against the candidates

  const ea_t func = opt.stay_in_function ? get_func_start(start) : BADADDR;  // BADADDR: not in a function

  ea_t ea = start;
  while (out.pattern.size() < opt.max_bytes) {
    if (user_cancelled()) {
      out.note = "cancelled";
      return false;
    }

    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
      out.note = "could not decode an instruction";
      break;
    }

    append_instruction(insn, opt, out.pattern);
    ++out.insn_count;

    if (!seeded) {
      // One full scan for the first instruction. Its opcode byte is never wildcarded,
      // so the pattern starts on a fixed byte and hit addresses are instruction starts.
      for (ea_t hit : image.find(out.pattern, SIZE_MAX, opt.code_only))
        if (hit != start)
          candidates.push_back(hit);

      seeded       = true;
      pending_from = out.pattern.size();
    } else {
      const size_t from = pending_from;
      const size_t need = out.pattern.size();
      std::vector<ea_t> kept;
      kept.reserve(candidates.size());

      for (ea_t c : candidates) {
        const uint8_t* p = image.at(c, need);
        if (!p)
          continue;

        bool ok = true;
        for (size_t i = from; i < need; ++i) {
          if (out.pattern.fixed[i] && p[i] != out.pattern.bytes[i]) {
            ok = false;
            break;
          }
        }
        if (ok)
          kept.push_back(c);
      }

      candidates.swap(kept);
      pending_from = need;
    }

    if (candidates.empty()) {
      out.unique = true;
      break;
    }

    ea += insn.size;
    if (func != BADADDR && get_func_start(ea) != func) {
      out.note = "reached the end of the function before the signature became unique";
      break;
    }
    if (!is_code(get_flags(ea))) {
      out.note = "reached the end of the code before the signature became unique";
      break;
    }
  }

  if (!out.unique && out.note.empty())
    out.note = "reached the maximum signature length";

  out.other_matches = candidates.size();

  // Trailing wildcards add nothing
  while (!out.pattern.fixed.empty() && !out.pattern.fixed.back()) {
    out.pattern.bytes.pop_back();
    out.pattern.fixed.pop_back();
  }

  return !out.pattern.empty();
}

bool generate_range(const image_t& image, ea_t start, ea_t end, const options_t& opt, generated_t& out) {
  out = generated_t();

  for (ea_t ea = start; ea < end;) {
    insn_t insn;
    if (decode_insn(&insn, ea) <= 0) {
      out.note = "could not decode an instruction";
      break;
    }
    append_instruction(insn, opt, out.pattern);
    ++out.insn_count;
    ea += insn.size;
  }

  // Not trimmed: these are exactly the bytes the user selected
  if (out.pattern.empty())
    return false;

  std::vector<ea_t> hits = image.find(out.pattern, SIZE_MAX, opt.code_only);
  size_t others = 0;
  for (ea_t h : hits)
    if (h != start)
      ++others;

  out.other_matches = others;
  out.unique        = others == 0;
  return true;
}

// ---------------------------------------------------------------------------
// xrefs
// ---------------------------------------------------------------------------

std::vector<ea_t> code_xrefs_to(ea_t target, size_t* data_refs) {
  std::vector<ea_t> sites;
  size_t            data = 0;

  xrefblk_t xb;
  for (bool ok = xb.first_to(target, XREF_ALL); ok; ok = xb.next_to()) {
    if (xb.iscode && xb.type != fl_F)  // fl_F is ordinary flow into the function, not a reference
      sites.push_back(xb.from);
    else if (!xb.iscode)
      ++data;
  }

  std::sort(sites.begin(), sites.end());
  sites.erase(std::unique(sites.begin(), sites.end()), sites.end());
  if (data_refs)
    *data_refs = data;
  return sites;
}

bool describe_branch(ea_t site, size_t& rel_offset, size_t& insn_size) {
  insn_t insn;
  if (decode_insn(&insn, site) <= 0)
    return false;

  for (int n = 0; n < UA_MAXOP; ++n) {
    const op_t& op = insn.ops[n];
    if (op.type == o_void)
      break;
    if ((op.type == o_near || op.type == o_far) && op.offb != 0) {
      rel_offset = op.offb;
      insn_size  = insn.size;
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// clipboard
// ---------------------------------------------------------------------------

bool copy_to_clipboard(const std::string& text) {
#ifdef _WIN32
  const size_t size = text.size() + 1;
  HGLOBAL      mem  = GlobalAlloc(GMEM_MOVEABLE, size);
  if (!mem)
    return false;

  void* dst = GlobalLock(mem);
  if (!dst) {
    GlobalFree(mem);
    return false;
  }
  memcpy(dst, text.c_str(), size);
  GlobalUnlock(mem);

  if (!OpenClipboard(nullptr)) {
    GlobalFree(mem);
    return false;
  }

  EmptyClipboard();
  // On success the clipboard owns the memory; only free it on failure
  if (!SetClipboardData(CF_TEXT, mem)) {
    CloseClipboard();
    GlobalFree(mem);
    return false;
  }
  CloseClipboard();
  return true;
#else
  (void)text;
  return false;
#endif
}

}  // namespace fusion
