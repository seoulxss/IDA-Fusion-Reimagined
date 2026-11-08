#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <functional>

#include "fusion.h"

namespace {

constexpr const char* ACTION_CREATE_IDA  = "fusion:create_ida";
constexpr const char* ACTION_CREATE_CODE = "fusion:create_code";
constexpr const char* ACTION_SEARCH      = "fusion:search";

enum mode_t : ushort { MODE_CREATE_IDA = 0, MODE_CREATE_CODE = 1, MODE_SEARCH = 2 };

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
  ushort            last_mode = MODE_CREATE_IDA;
  qstring           last_search;

  action_t create_ida_handler  { [this] { create_ida(); } };
  action_t create_code_handler { [this] { create_code(); } };
  action_t search_handler      { [this] { search(); } };

  plugin_ctx_t() {
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_CREATE_IDA,  "Create signature (IDA style)",  &create_ida_handler,  this, nullptr, nullptr, -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_CREATE_CODE, "Create signature (CODE style)", &create_code_handler, this, nullptr, nullptr, -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_SEARCH,      "Search for signature...",       &search_handler,      this, nullptr, nullptr, -1));

    hook_event_listener(HT_UI, this);
  }

  ~plugin_ctx_t() override {
    unhook_event_listener(HT_UI, this);
    unregister_action(ACTION_CREATE_IDA);
    unregister_action(ACTION_CREATE_CODE);
    unregister_action(ACTION_SEARCH);
  }

  // Add the entries to the context menu of disassembly views
  ssize_t idaapi on_event(ssize_t code, va_list va) override {
    if (code == ui_finish_populating_widget_popup) {
      TWidget* widget = va_arg(va, TWidget*);
      TPopupMenu* popup = va_arg(va, TPopupMenu*);

      if (get_widget_type(widget) == BWN_DISASM) {
        attach_action_to_popup(widget, popup, ACTION_CREATE_IDA,  "Fusion/");
        attach_action_to_popup(widget, popup, ACTION_CREATE_CODE, "Fusion/");
        attach_action_to_popup(widget, popup, ACTION_SEARCH,      "Fusion/");
      }
    }
    return 0;
  }

  bool idaapi run(size_t) override {
    ushort mode    = last_mode;
    ushort toggles = (options.wildcard_displ ? 1 : 0) | (options.wildcard_imm ? 2 : 0);

    // clang-format off
    static const char form[] =
        "STARTITEM 0\n"
        "BUTTON YES* Run\n"
        "Fusion\n\n"
        "<Create signature (IDA style, 48 8B ? ?):R>\n"
        "<Create signature (CODE style, \\x48\\x8B\\x00\\x00):R>\n"
        "<Search for a signature:R>>\n\n"
        "<Wildcard 32 bit displacements ([reg+disp32]):C>\n"
        "<Wildcard 32/64 bit immediates:C>>\n\n";
    // clang-format on

    if (ask_form(form, &mode, &toggles) <= 0)
      return true;

    last_mode                = mode;
    options.wildcard_displ   = (toggles & 1) != 0;
    options.wildcard_imm     = (toggles & 2) != 0;

    switch (mode) {
      case MODE_CREATE_IDA:  create_ida();  break;
      case MODE_CREATE_CODE: create_code(); break;
      case MODE_SEARCH:      search();      break;
    }
    return true;
  }

  void create_ida()  { create(fusion::style_t::ida); }
  void create_code() { create(fusion::style_t::code); }

  void create(fusion::style_t style) {
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

    const std::string ida_sig  = fusion::format(result.pattern, fusion::style_t::ida);
    const std::string code_sig = fusion::format(result.pattern, fusion::style_t::code);
    const std::string& chosen  = style == fusion::style_t::ida ? ida_sig : code_sig;

    const ea_t origin = has_selection ? sel_start : ea;
    msg("[Fusion] Signature for 0x%llX (%d bytes, %d instructions)\n",
        (unsigned long long)origin, (int)result.pattern.size(), (int)result.insn_count);
    msg("[Fusion] IDA : %s\n", ida_sig.c_str());
    msg("[Fusion] CODE: %s\n", code_sig.c_str());

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
