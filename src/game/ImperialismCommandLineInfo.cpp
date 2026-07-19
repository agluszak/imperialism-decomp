#include "game/ImperialismCommandLineInfo.h"

#include "game/CString.h"
#include "game/global_data_tables.h"

namespace {

// _mbscmp (0x5e7980) equality via the repo-typed declaration; the byte-pointer cast is
// confined here. Inlined at both compare sites (the original materializes the ==0 result
// as a byte: neg/sbb/inc + test al).
__inline char EqualsCommandToken(LPCSTR text, char* literal) {
  return _mbscmp(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(text)),
                 reinterpret_cast<unsigned char*>(literal)) == 0;
}

} // namespace

// FUNCTION: IMPERIALISM 0x004133d0
void ImperialismCommandLineInfo::ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast) {
  CString token(pszParam);
  token.MakeUpper();
  LPCSTR upper = token;
  if (bFlag && EqualsCommandToken(upper, g_szCmdSwitchLangQuit_00694254)) {
    m_bQuitAfterLanguageScan2c = 1;
    m_bShowSetupDialog30 = 1;
  } else if (bFlag && EqualsCommandToken(upper, g_szLiteralL_00694250)) {
    m_bShowSetupDialog30 = 1;
  } else if (bFlag && upper[0] == 'L') {
    *m_pLanguageName24 = pszParam + 1; // language name keeps its original case
  } else if (bFlag && upper[0] == 'R') {
    m_bForceAutoResOn3c = 1;
  } else if (bFlag && upper[0] == 'S') {
    m_bForceAutoResOff40 = 1;
  } else if (bFlag && upper[0] == 'T') {
    m_strMainWindowTitle38 = upper + 1;
  } else if (bFlag && upper[0] == 'C') {
    m_bClearRegistrySettings34 = 1;
  }
  CCommandLineInfo::ParseParam(pszParam, bFlag, bLast);
}

// SYNTHETIC: IMPERIALISM 0x00413550
// ImperialismCommandLineInfo::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00413580
ImperialismCommandLineInfo::~ImperialismCommandLineInfo() {}
