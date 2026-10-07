#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063e478
class ImperialismCommandLineInfo : public CCommandLineInfo {
public:
  explicit ImperialismCommandLineInfo(CString* languageName)
      : m_pLanguageName(languageName), field_28(0x20), m_bQuitAfterLanguageScan(0),
        m_bShowSetupDialog(0), m_bClearRegistrySettings(0), m_bForceAutoResOn(0),
        m_bForceAutoResOff(0) {}
  // FUNCTION: IMPERIALISM 0x00413580
  virtual ~ImperialismCommandLineInfo() override {}

  virtual void ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast) override;

  CString* m_pLanguageName;     // points at the caller's language CString
  unsigned char field_28;       // set to 0x20 at construction; no reader found yet
  int m_bQuitAfterLanguageScan; // 0x2c — "L!"
  int m_bShowSetupDialog;       // 0x30 — "L" or "L!"
  int m_bClearRegistrySettings; // 0x34 — "C"
  CString m_strMainWindowTitle; // "T<text>"
  int m_bForceAutoResOn;        // 0x3c — "R"
  int m_bForceAutoResOff;       // 0x40 — "S"
};
