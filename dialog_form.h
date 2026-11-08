#pragma once

// Format string of the main dialog, kept free of IDA includes so the tests can check it.
//
// ask_form() refuses a malformed string without a word -- the dialog just does not open,
// and the error IDA prints only names the start of the form body. What is known to break it:
//   - a ':' inside a label  (':' separates the label from the field type)
//   - a '#' inside a label  ('#' delimits hints)
// So labels use plain words, digits, '-', '/' and parentheses only; examples live in the README.
//
// "%/" declares the form-change callback: it fires with CB_INIT only if the form parsed, which
// is the only way to tell a refused string from the Search button (both return 0).
//
// "BUTTON NO" adds a third button. Return values: 1 = Run, 0 = Search pattern, -1 = cancelled.
//
// Arguments, in order:
//   formchgcb_t* callback, ushort* outputs (checkbox group 1), ushort* options (checkbox group 2)
//
// Group 1 has one checkbox per entry of STYLES in main.cpp, in the same order.

namespace fusion {

inline constexpr int DIALOG_OUTPUT_COUNT = 7;

// clang-format off
inline constexpr const char DIALOG_FORM[] =
    "STARTITEM 0\n"
    "BUTTON YES* Run\n"
    "BUTTON NO Search pattern...\n"
    "%/Fusion\n\n"
    "<Signature (IDA style):C>\n"
    "<Signature (CODE style):C>\n"
    "<Hash of signature - FNV-1a (32 bit):C>\n"
    "<Hash of signature - CRC-32:C>\n"
    "<Hash of signature - XXH32:C>\n"
    "<Hash of signature - XXH64:C>\n"
    "<Hash of signature - XXH128:C>>\n\n"
    "<Wildcard 32 bit displacements:C>\n"
    "<Wildcard 32/64 bit immediates:C>>\n\n";
// clang-format on

}  // namespace fusion
