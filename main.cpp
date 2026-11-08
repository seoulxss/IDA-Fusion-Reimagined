#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

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
  ushort            last_outputs = 3;  // IDA + CODE ticked on first use
  qstring           last_search;

  std::vector<std::unique_ptr<action_t>> handlers;  // one per STYLES entry, then search

  plugin_ctx_t() {
    for (const style_entry_t& e : STYLES) {
      handlers.push_back(std::make_unique<action_t>([this, s = e.style] { create(s); }));
      register_action(ACTION_DESC_LITERAL_PLUGMOD(e.action, e.label, handlers.back().get(), this, nullptr, nullptr, -1));
    }
    handlers.push_back(std::make_unique<action_t>([this] { search(); }));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_SEARCH, "Search for signature...", handlers.back().get(), this, nullptr, nullptr, -1));

    hook_event_listener(HT_UI, this);
  }

  ~plugin_ctx_t() override {
    unhook_event_listener(HT_UI, this);
    for (const style_entry_t& e : STYLES)
      unregister_action(e.action);
    unregister_action(ACTION_SEARCH);
  }

  // Add the entries to the context menu of disassembly views
  ssize_t idaapi on_event(ssize_t code, va_list va) override {
    if (code == ui_finish_populating_widget_popup) {
      TWidget* widget = va_arg(va, TWidget*);
      TPopupMenu* popup = va_arg(va, TPopupMenu*);

      if (get_widget_type(widget) == BWN_DISASM) {
        for (const style_entry_t& e : STYLES)
          attach_action_to_popup(widget, popup, e.action, e.menu);
        attach_action_to_popup(widget, popup, ACTION_SEARCH, "Fusion/");
      }
    }
    return 0;
  }

  bool idaapi run(size_t) override {
    ushort outputs = last_outputs;
    ushort toggles = (options.wildcard_displ ? 1 : 0) | (options.wildcard_imm ? 2 : 0);

    g_form_opened = false;
    const int answer = ask_form(fusion::DIALOG_FORM, &form_callback, &outputs, &toggles);

    if (answer == 0 && !g_form_opened) {
      // The callback never fired: IDA refused the format string (it also printed a warning)
      msg("[Fusion] The settings dialog could not be opened. Use the Fusion entries of the context menu instead.\n");
      return true;
    }
    if (answer < 0)
      return true;  // cancelled

    // Run (1) and Search (0) both keep the choices
    last_outputs           = outputs;
    options.wildcard_displ = (toggles & 1) != 0;
    options.wildcard_imm   = (toggles & 2) != 0;

    if (answer == 0)
      search();
    else
      create(outputs);
    return true;
  }

  static bool g_form_opened;
  static int idaapi form_callback(int field_id, form_actions_t&) {
    if (field_id == CB_INIT)
      g_form_opened = true;
    return 1;
  }

  void create(style_t style) { create(ushort(1u << style_index(style))); }

  static size_t style_index(style_t style) {
    for (size_t i = 0; i < STYLE_COUNT; ++i)
      if (STYLES[i].style == style)
        return i;
    return 0;
  }

  // `outputs`: bit i selects STYLES[i]
  void create(ushort outputs) {
    if ((outputs & ((1u << STYLE_COUNT) - 1)) == 0) {
      warning("[Fusion] Nothing selected. Tick at least one output in the dialog.");
      return;
    }

    const ea_t ea = get_screen_ea();

    ea_t sel_start = BADADDR, sel_end = BADADDR;
    const bool has_selection = read_range_selection(nullptr, &sel_start, &sel_end);

    if (!has_selection && !is_code(get_flags(ea))) {
      warning("[Fusion] 0x%llX is not code. Place the cursor on an instruction first.", (unsigned long long)ea);
      return;
    }

    fusion::image_t image;
    {
      wait_box_t wait("[Fusion] Reading database...");
      if (!image.capture()) {
        msg("[Fusion] Cancelled\n");
        return;
      }
    }

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
    msg("[Fusion] Signature for 0x%llX (%d bytes, %d instructions)\n",
        (unsigned long long)origin, (int)result.pattern.size(), (int)result.insn_count);

    // Only what was ticked is printed and copied. A single output is copied as is,
    // several are copied one per line with their name.
    std::string chosen;
    int         selected = 0;
    for (size_t i = 0; i < STYLE_COUNT; ++i)
      selected += (outputs >> i) & 1;

    for (size_t i = 0; i < STYLE_COUNT; ++i) {
      if (!((outputs >> i) & 1))
        continue;
      const std::string value = fusion::format(result.pattern, STYLES[i].style);
      msg("[Fusion] %-6s: %s\n", fusion::style_name(STYLES[i].style), value.c_str());

      if (selected == 1) {
        chosen = value;
      } else {
        if (!chosen.empty())
          chosen += "\r\n";
        chosen += std::string(fusion::style_name(STYLES[i].style)) + ": " + value;
      }
    }

    if (result.unique) {
      msg("[Fusion] Unique\n");
    } else {
      msg("[Fusion] NOT unique: %d other match%s%s%s\n", (int)result.other_matches,
          result.other_matches == 1 ? "" : "es", result.note.empty() ? "" : " - ", result.note.c_str());
    }

    if (fusion::copy_to_clipboard(chosen))
      msg("[Fusion] Copied to clipboard\n");
    else
      msg("[Fusion] Could not access the clipboard\n");

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

    fusion::image_t image;
    std::vector<ea_t> hits;
    {
      wait_box_t wait("[Fusion] Searching...");
      if (!image.capture()) {
        msg("[Fusion] Cancelled\n");
        return;
      }
      hits = image.find(pattern);
    }

    if (hits.empty()) {
      msg("[Fusion] No match for %s\n", fusion::format(pattern, fusion::style_t::ida).c_str());
      return;
    }

    for (size_t i = 0; i < hits.size(); ++i)
      msg("[Fusion] %d. 0x%llX\n", (int)(i + 1), (unsigned long long)hits[i]);
    msg("[Fusion] %d match%s\n", (int)hits.size(), hits.size() == 1 ? "" : "es");

    jumpto(hits.front());
    beep(beep_default);
  }
};

bool plugin_ctx_t::g_form_opened = false;

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
