#include "game/ImperialismCommandLineInfo.h"

#include <mbstring.h>

#include "game/core/CString.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x004133d0
void ImperialismCommandLineInfo::ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast) {
  CString token(pszParam);
  token.MakeUpper();
  LPCSTR upper = token;
  if (bFlag && token.Compare(g_szCmdSwitchLangQuit_00694254) == 0) {
    m_bQuitAfterLanguageScan = 1;
    m_bShowSetupDialog = 1;
  } else if (bFlag && token.Compare(g_szLiteralL_00694250) == 0) {
    m_bShowSetupDialog = 1;
  } else if (bFlag && upper[0] == 'L') {
    *m_pLanguageName = pszParam + 1; // language name keeps its original case
  } else if (bFlag && upper[0] == 'R') {
    m_bForceAutoResOn = 1;
  } else if (bFlag && upper[0] == 'S') {
    m_bForceAutoResOff = 1;
  } else if (bFlag && upper[0] == 'T') {
    m_strMainWindowTitle = upper + 1;
  } else if (bFlag && upper[0] == 'C') {
    m_bClearRegistrySettings = 1;
  }
  CCommandLineInfo::ParseParam(pszParam, bFlag, bLast);
}
