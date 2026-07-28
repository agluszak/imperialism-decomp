#include "game/ImperialismCommandLineInfo.h"

#include "game/core/CString.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x004133d0
void ImperialismCommandLineInfo::ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast) {
  CString token(pszParam);
  token.MakeUpper();
  LPCSTR upper = token;
  if (bFlag && token.Compare(g_szCmdSwitchLangQuit_00694254) == 0) {
    m_bQuitAfterLanguageScan2c = 1;
    m_bShowSetupDialog30 = 1;
  } else if (bFlag && token.Compare(g_szLiteralL_00694250) == 0) {
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
