// Copyright 2026 seoulxss
// Licensed under the Apache License, Version 2.0, see LICENSE and NOTICE.
// Based on IDA-Fusion by senator715 (Apache-2.0); substantially modified, see the git history.

#pragma once

// Format string of the main dialog, kept free of IDA includes so the tests can check it.
//
// ask_form() refuses a malformed string without a word -- the dialog just does not open,
// and the error IDA prints only names the start of the form body. What is known to break it:
//   - a ':' inside a label  (':' separates the label from the field type)
//   - a '#' inside a label  ('#' delimits hints)
// So labels use plain words, digits, '-', '/' and parentheses only; examples live in the README.
//
// Deliberately plain: only radio and checkbox groups, no "%/" callback and no "BUTTON NO".
// IDA 9.5 crashed (jump through a dangling stack object, after the dialog closed) with a
// form-change callback together with a third button; the previous radio + checkbox layout was fine.
//
// Arguments, in order:
//   ushort* action   (radio group: 0 = create, 1 = search, 2 = XREFs of the function)
//   ushort* outputs  (checkbox group, one checkbox per entry of STYLES in main.cpp, same order)
//   ushort* options  (checkbox group, bits OPT_* in main.cpp, same order)

namespace fusion {

inline constexpr int DIALOG_OUTPUT_COUNT = 7;
inline constexpr int DIALOG_OPTION_COUNT = 6;

// clang-format off
inline constexpr const char DIALOG_FORM[] =
    "STARTITEM 0\n"
    "BUTTON YES* Run\n"
    "Fusion\n\n"
    "<Create (the ticked outputs below):R>\n"
    "<Search for a pattern in the database:R>\n"
    "<Signatures for the XREFs to this function (call sites):R>>\n\n"
    "<Signature (IDA style):C>\n"
    "<Signature (CODE style):C>\n"
    "<Hash of signature - FNV-1a (32 bit):C>\n"
    "<Hash of signature - CRC-32:C>\n"
    "<Hash of signature - XXH32:C>\n"
    "<Hash of signature - XXH64:C>\n"
    "<Hash of signature - XXH128:C>>\n\n"
    "<Wildcard 32 bit displacements:C>\n"
    "<Wildcard 32/64 bit immediates:C>\n"
    "<Only scan executable segments (faster):C>\n"
    "<Stay inside the function:C>\n"
    "<IDA style - use ?? as wildcard:C>\n"
    "<CODE style - always append the mask (xx??):C>>\n\n";
// clang-format on

}  // namespace fusion
