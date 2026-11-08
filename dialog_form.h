#pragma once

// Format string of the main dialog, kept free of IDA includes so the tests can check it.
//
// ask_form() refuses a malformed string without a word -- the dialog just does not open,
// and the error IDA prints only names the start of the form body. What is known to break it:
//   - a ':' inside a label  (':' separates the label from the field type)
//   - a '#' inside a label  ('#' delimits hints)
// So labels use plain words, digits, '-', '/' and parentheses only; examples live in the README.
//
// Arguments: ushort* mode (radio group), ushort* toggles (checkbox group).

namespace fusion {

// clang-format off
inline constexpr const char DIALOG_FORM[] =
    "STARTITEM 0\n"
    "BUTTON YES* Run\n"
    "Fusion\n\n"
    "<Create signature (IDA style):R>\n"
    "<Create signature (CODE style):R>\n"
    "<Hash of signature - FNV-1a (32 bit):R>\n"
    "<Hash of signature - CRC-32:R>\n"
    "<Hash of signature - XXH32:R>\n"
    "<Hash of signature - XXH64:R>\n"
    "<Hash of signature - XXH128:R>\n"
    "<Search for a signature:R>>\n\n"
    "<Wildcard 32 bit displacements:C>\n"
    "<Wildcard 32/64 bit immediates:C>>\n\n";
// clang-format on

}  // namespace fusion
