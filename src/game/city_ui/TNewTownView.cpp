#include "game/city_ui/TNewTownView.h"
#include "game/resource_domain_types.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TIconBar.h"
#include "game/ui_widgets/TTown.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004bd810
// TNewTownView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004bd840
TNewTownView::~TNewTownView() {}
// SYNTHETIC: IMPERIALISM 0x004bd7a0
// TNewTownView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004bd860
// TNewTownView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewTownView, TView)

// NOOP: verified empty in original 0x004bd7d3 (no standalone TNewTownView::TNewTownView body exists: CreateObject 0x004bd7a0 inlines this default ctor, calling the TView base ctor directly at that site)
TNewTownView::TNewTownView() {}

// FUNCTION: IMPERIALISM 0x004bd880
void TNewTownView::StuffValues(TTown* town) {
  CString townName;
  town60 = town;
  town->CalculateRawResources();

  int visibleResourceCount = 0;
  for (int countedResourceType = 0; countedResourceType < kResourceKindCount;
       ++countedResourceType) {
    if (town->resourceYieldByType[countedResourceType] != 0) {
      ++visibleResourceCount;
    }
  }
  int extraHeight = visibleResourceCount * 0x20;

  TView* owner = GetWindow();
  if (owner == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x7fa);
  }
  CRect bounds;
  owner->QueryBounds(&bounds);
  bounds.bottom += extraHeight;
  owner->ApplyBounds(&bounds, 1);

  QueryBounds(&bounds);
  bounds.bottom += extraHeight;
  ApplyBounds(&bounds, 1);

  TView* cancel = ResolveControlByTag(kControlTagCncl); // 'cncl'
  if (cancel == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x806);
  }
  cancel->QueryBounds(&bounds);
  OffsetRect(&bounds, 0, extraHeight);
  cancel->ApplyBounds(&bounds, 1);

  TView* okay = ResolveControlByTag(kControlTagOkay); // 'okay'
  if (okay == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x80c);
  }
  okay->QueryBounds(&bounds);
  OffsetRect(&bounds, 0, extraHeight);
  okay->ApplyBounds(&bounds, 1);

  int y = 0x40;
  for (short iconResourceType = 0; iconResourceType < kResourceKindCount; ++iconResourceType) {
    short amount = town->resourceYieldByType[iconResourceType];
    if (amount != 0) {
      TIconBar* iconBar = new TIconBar();
      int position[2] = {0x18, y};
      int size[2] = {frameWidth34 - 0x20, 0x10};
      iconBar->IIconBar(this, position, size, 5, 5, static_cast<short>(iconResourceType + 700),
                        amount);
      iconBar->RefreshControl();
      y += 0x20;
    }
  }

  TEditText* name = static_cast<TEditText*>(ResolveControlByTag(kControlTagName)); // 'name'
  if (name == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x821);
  }
  name->BecomeTarget();
  name->GetCurrentText(&townName);
  name->SetEditSelectionAndScrollCaret(0, static_cast<short>(townName.GetLength()), 1);
}

// FUNCTION: IMPERIALISM 0x004bdc10
void TNewTownView::Close() {
  CString townName;
  TEditText* nameControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagName)); // 'name'
  if (nameControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x82e);
  }
  nameControl->GetCurrentText(&townName);
  town60->SetName(static_cast<LPCSTR>(townName));
  TView::Close();
}
