#include "game/app/TTechStorePage.h"

#include "game/ui_screens/TBook.h"
#include "game/tactical_ui/TTechItemLine.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004600c0
TTechStorePage::TTechStorePage() {}

// TTechStorePage's vtable (0x645ca8) is a TPageView clone: only slot 0x00
// (GetRuntimeClass, via IMPLEMENT_DYNCREATE) and the scalar deleting destructor
// differ; every other slot is inherited unchanged from TPageView. The functions
// that the auto-recovery previously attributed here (0x479440/0x4796xx and the
// 0x606xxx/0x610xxx/0x611xxx MFC addresses) belong to the adjacent TScroller
// vtable / MFC library, not to TTechStorePage.

// SYNTHETIC: IMPERIALISM 0x004600f0
// TTechStorePage::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00460120
TTechStorePage::~TTechStorePage() {}

// SYNTHETIC: IMPERIALISM 0x005b0e70
// TTechStorePage::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b0ef0
// TTechStorePage::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechStorePage, TPageView)

// FUNCTION: IMPERIALISM 0x005b0f10
void TTechStorePage::PopulateUnlockedTechnologyRows(int nationSlot) {
  for (int techId = 0x1c; techId > 0; --techId) {
    if (g_pCityOrderCapabilityState->perTechUnlockFlag180[techId] != 0) {
      TTechItemLine* line = new TTechItemLine();
      int lineBounds[2] = {0x232, 0x3f};
      line->SetLineDataRowAndBounds(0, 0, lineBounds);
      line->nationSlot10 = nationSlot;
      line->techId14 = techId;
      AddOrderedEntry(line);
    }
  }
  BuildPageLayout();
  ShowPage(1);
  static_cast<TBook*>(ownerContext)->ShowPage(currentPage);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), controlTag);
}
