#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <registry.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <vector>

#include "dialog_form.h"
#include "fusion.h"

namespace {

using fusion::style_t;

struct style_entry_t {
  style_t     style;
  const char* action;  // action name
  const char* label;   // menu label
  const char* menu;    // popup submenu
};

// The order here is the order of the checkboxes in the dialog
constexpr style_entry_t STYLES[] = {
    {style_t::ida,    "fusion:create_ida",    "Create signature (IDA style)",  "Fusion/"},
    {style_t::code,   "fusion:create_code",   "Create signature (CODE style)", "Fusion/"},
    {style_t::fnv1a,  "fusion:create_fnv1a",  "FNV-1a (32 bit)",               "Fusion/Hash of signature/"},
    {style_t::crc32,  "fusion:create_crc32",  "CRC-32",                        "Fusion/Hash of signature/"},
    {style_t::xxh32,  "fusion:create_xxh32",  "XXH32",                         "Fusion/Hash of signature/"},
    {style_t::xxh64,  "fusion:create_xxh64",  "XXH64",                         "Fusion/Hash of signature/"},
    {style_t::xxh128, "fusion:create_xxh128", "XXH128",                        "Fusion/Hash of signature/"},
};
constexpr ushort STYLE_COUNT = sizeof(STYLES) / sizeof(STYLES[0]);
static_assert(STYLE_COUNT == fusion::DIALOG_OUTPUT_COUNT, "dialog has one checkbox per output");

constexpr const char* ACTION_SEARCH = "fusion:search";
constexpr const char* ACTION_XREF   = "fusion:xref";

// Radio group of the dialog
enum dialog_action_t : ushort { ACT_CREATE = 0, ACT_SEARCH = 1, ACT_XREF = 2 };

// Bits of the option checkbox group of the dialog (same order as in dialog_form.h)
enum : ushort {
  OPT_DISPL    = 1 << 0,
  OPT_IMM      = 1 << 1,
  OPT_CODEONLY = 1 << 2,
  OPT_FUNCTION = 1 << 3,
  OPT_DQ       = 1 << 4,
  OPT_MASK     = 1 << 5,
};
static_assert(fusion::DIALOG_OPTION_COUNT == 6, "dialog has one checkbox per OPT_* bit");

// Keeps the wait box balanced even on early returns
struct wait_box_t {
  explicit wait_box_t(const char* text) { show_wait_box("%s", text); }
  ~wait_box_t() { hide_wait_box(); }
  void update(const char* text) { replace_wait_box("%s", text); }
};

struct action_t : action_handler_t {
  std::function<void()> fn;

  explicit action_t(std::function<void()> f) : fn(std::move(f)) {}

  int idaapi activate(action_activation_ctx_t*) override {
    fn();
    return 1;
  }
  action_state_t idaapi update(action_update_ctx_t*) override { return AST_ENABLE_ALWAYS; }
};

struct plugin_ctx_t : public plugmod_t, public event_listener_t {
  fusion::options_t options;
  ushort            last_action  = ACT_CREATE;
  ushort            last_outputs = 3;  // IDA + CODE ticked on first use
  qstring           last_search;

  std::vector<std::unique_ptr<action_t>> handlers;  // one per STYLES entry, then search and xref

  // The snapshot of the database is kept between runs, so the second search does not read it again.
  // Anything that changes bytes or segments throws it away.
  fusion::image_t image_cache;
  static constexpr size_t CACHE_LIMIT = size_t(512) << 20;  // do not keep more than this in memory

  struct idb_watch_t : public event_listener_t {
    plugin_ctx_t* owner;
    explicit idb_watch_t(plugin_ctx_t* o) : owner(o) {}
    ssize_t idaapi on_event(ssize_t code, va_list) override {
      switch (code) {
        case idb_event::byte_patched:
        case idb_event::segm_added:
        case idb_event::segm_deleted:
        case idb_event::segm_start_changed:
        case idb_event::segm_end_changed:
        case idb_event::segm_moved:
        case idb_event::allsegs_moved:
          owner->image_cache.clear();
          break;
      }
      return 0;
    }
  } idb_watch{this};

  // --- settings, kept in IDA's per-user registry so they survive restarts ---------------------------

  ushort option_bits() const {
    return (options.wildcard_displ ? OPT_DISPL : 0) | (options.wildcard_imm ? OPT_IMM : 0) |
           (options.code_only ? OPT_CODEONLY : 0) | (options.stay_in_function ? OPT_FUNCTION : 0) |
           (options.double_question ? OPT_DQ : 0) | (options.code_mask ? OPT_MASK : 0);
  }

  void set_option_bits(ushort bits) {
    options.wildcard_displ   = (bits & OPT_DISPL) != 0;
    options.wildcard_imm     = (bits & OPT_IMM) != 0;
    options.code_only        = (bits & OPT_CODEONLY) != 0;
    options.stay_in_function = (bits & OPT_FUNCTION) != 0;
    options.double_question  = (bits & OPT_DQ) != 0;
    options.code_mask        = (bits & OPT_MASK) != 0;
  }

  void load_settings() {
    last_action  = (ushort)reg_read_int("Fusion.action", ACT_CREATE);
    last_outputs = (ushort)reg_read_int("Fusion.outputs", last_outputs);
    set_option_bits((ushort)reg_read_int("Fusion.options", option_bits()));

    if (last_action > ACT_XREF)
      last_action = ACT_CREATE;
    last_outputs &= (1u << STYLE_COUNT) - 1;
  }

  void save_settings() const {
    reg_write_int("Fusion.action", last_action);
    reg_write_int("Fusion.outputs", last_outputs);
    reg_write_int("Fusion.options", option_bits());
  }

  // --- snapshot ----------------------------------------------------------------------------------------

  bool load_image() {
    wait_box_t wait("[Fusion] Reading database...");
    if (image_cache.capture(options.code_only))
      return true;
    msg("[Fusion] Cancelled\n");
    return false;
  }

  void trim_cache() {
    if (image_cache.total_bytes() > CACHE_LIMIT)
      image_cache.clear();
  }

  // --- plugin ------------------------------------------------------------------------------------------

  plugin_ctx_t() {
    load_settings();

    for (const style_entry_t& e : STYLES) {
      handlers.push_back(std::make_unique<action_t>([this, s = e.style] { create(s); }));
      register_action(ACTION_DESC_LITERAL_PLUGMOD(e.action, e.label, handlers.back().get(), this, nullptr, nullptr, -1));
    }
    handlers.push_back(std::make_unique<action_t>([this] { search(); }));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_SEARCH, "Search for signature...", handlers.back().get(), this, nullptr, nullptr, -1));
    handlers.push_back(std::make_unique<action_t>([this] { create_xref(last_outputs ? last_outputs : ushort(1)); }));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_XREF, "Create signatures for the XREFs to this function", handlers.back().get(), this, nullptr, nullptr, -1));

    hook_event_listener(HT_UI, this);
    hook_event_listener(HT_IDB, &idb_watch);
  }

  ~plugin_ctx_t() override {
    unhook_event_listener(HT_IDB, &idb_watch);
    unhook_event_listener(HT_UI, this);
    for (const style_entry_t& e : STYLES)
      unregister_action(e.action);
    unregister_action(ACTION_SEARCH);
    unregister_action(ACTION_XREF);
  }

  // Add the entries to the context menu of disassembly views
  ssize_t idaapi on_event(ssize_t code, va_list va) override {
    if (code == ui_finish_populating_widget_popup) {
      TWidget* widget = va_arg(va, TWidget*);
      TPopupMenu* popup = va_arg(va, TPopupMenu*);

      if (get_widget_type(widget) == BWN_DISASM) {
        for (const style_entry_t& e : STYLES)
          attach_action_to_popup(widget, popup, e.action, e.menu);
        attach_action_to_popup(widget, popup, ACTION_XREF, "Fusion/");
        attach_action_to_popup(widget, popup, ACTION_SEARCH, "Fusion/");
      }
    }
    return 0;
  }

  bool idaapi run(size_t) override {
    ushort action  = last_action;
    ushort outputs = last_outputs;
    ushort toggles = option_bits();

    // 0 = cancelled (or IDA refused the format string, which it reports with a warning)
    if (ask_form(fusion::DIALOG_FORM, &action, &outputs, &toggles) <= 0)
      return true;

    last_action  = action;
    last_outputs = outputs;
    set_option_bits(toggles);
    save_settings();

    if (action == ACT_SEARCH)
      search();
    else if (action == ACT_XREF)
      create_xref(outputs);
    else
      create(outputs);
    return true;
  }

  void create(style_t style) { create(ushort(1u << style_index(style))); }

  static size_t style_index(style_t style) {
    for (size_t i = 0; i < STYLE_COUNT; ++i)
      if (STYLES[i].style == style)
        return i;
    return 0;
  }

  static bool nothing_selected(ushort outputs) {
    if ((outputs & ((1u << STYLE_COUNT) - 1)) != 0)
      return false;
    warning("[Fusion] Nothing selected. Tick at least one output in the dialog.");
    return true;
  }

  // Prints the ticked outputs of a signature and returns the text for the clipboard: a single output as is,
  // several one per line with their name.
  std::string print_outputs(const fusion::generated_t& result, ushort outputs) const {
    std::string chosen;
    int         selected = 0;
    for (size_t i = 0; i < STYLE_COUNT; ++i)
      selected += (outputs >> i) & 1;

    for (size_t i = 0; i < STYLE_COUNT; ++i) {
      if (!((outputs >> i) & 1))
        continue;
      const std::string value = fusion::format(result.pattern, STYLES[i].style, options);
      msg("[Fusion] %-6s: %s\n", fusion::style_name(STYLES[i].style), value.c_str());

      if (selected == 1) {
        chosen = value;
      } else {
        if (!chosen.empty())
          chosen += "\r\n";
        chosen += std::string(fusion::style_name(STYLES[i].style)) + ": " + value;
      }
    }
    return chosen;
  }

  // How to get from a match of an XREF signature to the function: the signature starts at the call/jump, whose
  // 32 bit displacement is relative to the end of the instruction. Verified against the real target here.
  static std::string resolve_text(ea_t site, ea_t target) {
    size_t rel = 0, len = 0;
    if (!fusion::describe_branch(site, rel, len))
      return "resolve: not a direct call/jump with an encoded displacement (indirect), cannot be resolved this way";

    const int32 disp     = (int32)get_dword(site + rel);
    const ea_t  computed = site + len + (ea_t)(int64)disp;

    char buf[256];
    qsnprintf(buf, sizeof(buf), "resolve: target = match + %d + int32 at (match + %d)   -> 0x%llX (%s)", (int)len,
              (int)rel, (unsigned long long)computed, computed == target ? "checked, this is the function" : "DOES NOT MATCH");
    return buf;
  }

  // The same step as C++ you can paste next to your scanner (`match` is the address the scan returned)
  static void print_cpp_line(ea_t site, const char* indent) {
    size_t rel = 0, len = 0;
    if (!fusion::describe_branch(site, rel, len))
      return;
    msg("[Fusion] %sC++: %s\n", indent, fusion::cpp_resolve_line(rel, len).c_str());
  }

  static void copy(const std::string& text) {
    if (fusion::copy_to_clipboard(text))
      msg("[Fusion] Copied to clipboard\n");
    else
      msg("[Fusion] Could not access the clipboard\n");
  }

  static double seconds_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  }

  // `outputs`: bit i selects STYLES[i]
  void create(ushort outputs) {
    if (nothing_selected(outputs))
      return;

    const ea_t ea = get_screen_ea();

    ea_t sel_start = BADADDR, sel_end = BADADDR;
    const bool has_selection = read_range_selection(nullptr, &sel_start, &sel_end);

    if (!has_selection && !is_code(get_flags(ea))) {
      warning("[Fusion] 0x%llX is not code. Place the cursor on an instruction first.", (unsigned long long)ea);
      return;
    }

    const auto t0 = std::chrono::steady_clock::now();

    if (!load_image())
      return;
    const fusion::image_t& image = image_cache;

    fusion::generated_t result;
    bool ok;
    {
      wait_box_t wait(has_selection ? "[Fusion] Creating signature for the selection..." : "[Fusion] Creating signature...");
      ok = has_selection ? fusion::generate_range(image, sel_start, sel_end, options, result)
                         : fusion::generate(image, ea, options, result);
    }

    if (!ok) {
      msg("[Fusion] No signature created%s%s\n", result.note.empty() ? "" : ": ", result.note.c_str());
      return;
    }

    const ea_t origin = has_selection ? sel_start : ea;
    msg("[Fusion] Signature for 0x%llX (%d bytes, %d instructions, %.3fs)\n",
        (unsigned long long)origin, (int)result.pattern.size(), (int)result.insn_count, seconds_since(t0));

    const std::string chosen = print_outputs(result, outputs);

    if (result.unique) {
      msg("[Fusion] Unique\n");
    } else {
      msg("[Fusion] NOT unique: %d other match%s%s%s\n", (int)result.other_matches,
          result.other_matches == 1 ? "" : "es", result.note.empty() ? "" : " - ", result.note.c_str());
    }

    copy(chosen);
    msg("\n");
    trim_cache();
    beep(beep_default);
  }

  // A signature for every place that calls (or jumps to) this function. The signature starts at the call
  // instruction, so it finds the call site; the target is the call's rel32 (see the offsets printed).
  // Useful when the function itself has no unique start.
  void create_xref(ushort outputs) {
    if (nothing_selected(outputs))
      return;

    ea_t target = get_func_start(get_screen_ea());
    if (target == BADADDR)
      target = get_screen_ea();

    size_t            data_refs = 0;
    std::vector<ea_t> sites     = fusion::code_xrefs_to(target, &data_refs);

    if (sites.empty()) {
      if (data_refs > 0)
        warning("[Fusion] No code XREFs to 0x%llX.\n\n%d data XREF(s) found: the function is probably called through "
                "a vtable (virtual call).\n\nSign the vtable entry or a function that calls it directly instead.",
                (unsigned long long)target, (int)data_refs);
      else
        warning("[Fusion] No XREFs to 0x%llX.", (unsigned long long)target);
      return;
    }

    const auto t0 = std::chrono::steady_clock::now();
    msg("[Fusion] %d XREF(s) to 0x%llX\n", (int)sites.size(), (unsigned long long)target);

    if (!load_image())
      return;

    struct row_t {
      ea_t                site;
      fusion::generated_t sig;
    };
    std::vector<row_t> rows;

    {
      wait_box_t wait("[Fusion] Creating signatures...");
      for (size_t i = 0; i < sites.size(); ++i) {
        if (user_cancelled()) {
          msg("[Fusion] Cancelled\n");
          break;
        }
        replace_wait_box("[Fusion] Creating signature %d/%d...", (int)(i + 1), (int)sites.size());

        row_t row;
        row.site = sites[i];
        if (is_code(get_flags(row.site)) && fusion::generate(image_cache, row.site, options, row.sig) && row.sig.unique)
          rows.push_back(std::move(row));
      }
    }

    if (rows.empty()) {
      warning("[Fusion] No unique signature could be created for any of the %d call site(s).", (int)sites.size());
      trim_cache();
      return;
    }

    std::stable_sort(rows.begin(), rows.end(),
                     [](const row_t& a, const row_t& b) { return a.sig.pattern.size() < b.sig.pattern.size(); });

    // The first ticked output is used for the list; the shortest signature gets all of them
    size_t first = 0;
    while (first < STYLE_COUNT && !((outputs >> first) & 1))
      ++first;

    constexpr size_t MAX_LISTED = 40;
    for (size_t i = 0; i < rows.size() && i < MAX_LISTED; ++i) {
      qstring     name;
      get_func_name(&name, rows[i].site);
      msg("[Fusion] XREF %d  call site 0x%llX in %s\n", (int)(i + 1), (unsigned long long)rows[i].site,
          name.empty() ? "?" : name.c_str());
      msg("[Fusion]   signature: %s\n", fusion::format(rows[i].sig.pattern, STYLES[first].style, options).c_str());
      msg("[Fusion]   %s\n", resolve_text(rows[i].site, target).c_str());
      print_cpp_line(rows[i].site, "  ");
      msg("\n");  // blank line between the entries
    }
    if (rows.size() > MAX_LISTED)
      msg("[Fusion] ... and %d more\n\n", (int)(rows.size() - MAX_LISTED));

    msg("[Fusion] %d of %d call site(s) have a unique signature (%.3fs), shortest first\n\n", (int)rows.size(),
        (int)sites.size(), seconds_since(t0));
    msg("[Fusion] The shortest one (XREF 1, %d bytes) finds the CALL SITE, not the function itself:\n",
        (int)rows[0].sig.pattern.size());
    const std::string clip = print_outputs(rows[0].sig, outputs);
    msg("[Fusion] %s\n", resolve_text(rows[0].site, target).c_str());
    print_cpp_line(rows[0].site, "");
    copy(clip);
    msg("\n");

    trim_cache();
    beep(beep_default);
  }

  void search() {
    if (!ask_str(&last_search, HIST_SRCH, "Fusion - enter a signature (IDA or CODE style)"))
      return;

    fusion::pattern_t pattern;
    std::string       error;
    if (!fusion::parse(last_search.c_str(), pattern, error)) {
      warning("[Fusion] Invalid signature: %s", error.c_str());
      return;
    }

    if (!load_image())
      return;

    std::vector<ea_t> hits;
    {
      wait_box_t wait("[Fusion] Searching...");
      hits = image_cache.find(pattern, SIZE_MAX, options.code_only);
    }
    trim_cache();

    if (hits.empty()) {
      msg("[Fusion] No match for %s\n\n", fusion::format(pattern, fusion::style_t::ida, options).c_str());
      return;
    }

    for (size_t i = 0; i < hits.size(); ++i)
      msg("[Fusion] %d. 0x%llX\n", (int)(i + 1), (unsigned long long)hits[i]);
    msg("[Fusion] %d match%s\n", (int)hits.size(), hits.size() == 1 ? "" : "es");

    // Exactly one match: go there. With several there is no right answer, so stay where we are.
    if (hits.size() == 1) {
      jumpto(hits.front());
      msg("[Fusion] Jumped to 0x%llX\n", (unsigned long long)hits.front());
    } else {
      msg("[Fusion] Not jumping, the pattern is not unique\n");
    }
    msg("\n");
    beep(beep_default);
  }
};

plugmod_t* idaapi plugin_init() {
  // The signature code is x86/x64 specific only in how operands get wildcarded;
  // everything else works on any processor, so do not restrict the load.
  return new plugin_ctx_t;
}

}  // namespace

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    plugin_init,
    nullptr,
    nullptr,
    "Fast signature creator and scanner",
    "Create unique byte signatures from code and search for them.\n"
    "Also available from the context menu of the disassembly view (Fusion/).",
    "Fusion",
    "Ctrl-Alt-S",
};
