#include "game/TLanguageMgr.h"

#include "game/ImperialismApp.h"
#include "game/diplomacy_globals.h"

namespace {
const char kNewsTexPath[] = "news.tex";
const char kNewsTabPath[] = "news.tab";
const char kPreplutPath[] = "preplut.";
} // namespace

// FUNCTION: IMPERIALISM 0x00507c60
TLanguageMgr::TLanguageMgr() : TObject() {
  field8 = 0;
  field10 = 0;
  field1c = 0;
  field20 = 0;
  field24 = 0;
  newsTexPath = kNewsTexPath;
  newsTabPath = kNewsTabPath;
  field25 = 0x20;
  field30 = 6;
}

CRuntimeClass* TLanguageMgr::GetRuntimeClass() const { return 0; }

TLanguageMgr::~TLanguageMgr() {}

void TLanguageMgr::Free() {}

// FUNCTION: IMPERIALISM 0x005086a0
void ReloadPreplutNewsTableAndResources(int languageTag) {
  if (g_pLanguageMgr == nullptr) {
    return;
  }
  (void)languageTag;
  // TODO: FreeNestedPointerTableRowsAndResetDimensions, LoadNewsTabTexResourcesAndBuildEntries.
  CString preplutPath(kPreplutPath);
  if (DAT_006a1348 != nullptr) {
    preplutPath = DAT_006a1348->field_E0;
  }
  (void)preplutPath;
}
