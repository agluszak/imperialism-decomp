#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

// Command-line parser for Imperialism (original TU Imperialism.cpp). Stack-constructed
// with a fully inlined constructor in ImperialismApp::InitInstance (0x412dc0),
// ImperialismApp::LoadLanguageResourcesFromIrgFiles (0x4149a0) and
// ImperialismApp::ShowAutoResolutionDialogIfNeeded (0x415090).
//
// Switches are matched case-insensitively (ParseParam upper-cases a copy of the token):
//   L<name> -> *m_pLanguageName24 = "<name>" (language override, original case kept)
//   L       -> m_bShowSetupDialog30 (re-show the resolution/setup prompt)
//   L!      -> m_bShowSetupDialog30 + m_bQuitAfterLanguageScan2c
//              (LoadLanguageResourcesFromIrgFiles then returns FALSE and startup aborts)
//   R / S   -> force auto-resolution mode on (m_bForceAutoResOn3c) / off (m_bForceAutoResOff40)
//   T<text> -> m_strMainWindowTitle38 (upper-cased tail; SetWindowText on the main view host)
//   C       -> m_bClearRegistrySettings34 (InitInstance deletes the Settings key and exits,
//              same branch as the /Unregister shell command)
// VTABLE: IMPERIALISM 0x0063e478
class ImperialismCommandLineInfo : public CCommandLineInfo {
public:
  // Inlined at every construction site in the original; keep the definition in-class.
  explicit ImperialismCommandLineInfo(CString* languageName)
      : m_pLanguageName24(languageName), field_28(0x20), m_bQuitAfterLanguageScan2c(0),
        m_bShowSetupDialog30(0), m_bClearRegistrySettings34(0), m_strMainWindowTitle38(),
        m_bForceAutoResOn3c(0), m_bForceAutoResOff40(0) {}
  virtual ~ImperialismCommandLineInfo(); // 0x00413580

  virtual void ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast); // 0x004133d0

  CString* m_pLanguageName24;       // 0x24 — points at the caller's language CString
  unsigned char field_28;           // 0x28 — set to 0x20 at construction; no reader found yet
  int m_bQuitAfterLanguageScan2c;   // 0x2c — "L!"
  int m_bShowSetupDialog30;         // 0x30 — "L" or "L!"
  int m_bClearRegistrySettings34;   // 0x34 — "C"
  CString m_strMainWindowTitle38;   // 0x38 — "T<text>"
  int m_bForceAutoResOn3c;          // 0x3c — "R"
  int m_bForceAutoResOff40;         // 0x40 — "S"
};
