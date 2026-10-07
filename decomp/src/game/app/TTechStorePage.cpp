#include "game/app/TTechStorePage.h"

#include "game/ui_screens/TBook.h"
#include "game/tactical_ui/TTechItemLine.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004600c0
TTechStorePage::TTechStorePage() {}

// FUNCTION: IMPERIALISM 0x00460120
TTechStorePage::~TTechStorePage() {}

IMPLEMENT_DYNCREATE(TTechStorePage, TPageView)

// FUNCTION: IMPERIALISM 0x005b0f10
void TTechStorePage::StuffValues(int nationSlot) {
  for (int techId = 0x1c; techId > 0; --techId) {
    if (g_pTechMgr->perTechUnlockFlag[techId] != 0) {
      TTechItemLine* line = new TTechItemLine();
      int lineBounds[2] = {0x232, 0x3f};
      line->ILineData(0, 0, lineBounds);
      line->nationSlot = nationSlot;
      line->techId = techId;
      AddOrderedEntry(line);
    }
  }
  CalculatePageStarts();
  ShowPage(1);
  static_cast<TBook*>(ownerContext)->ShowPage(currentPage);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), controlTag);
}
