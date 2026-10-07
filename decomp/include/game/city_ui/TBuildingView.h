#pragma once

#include "compat.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

class TCity;
class TCityProductionView;
class TStaticText;
class TStaticText;

// VTABLE: IMPERIALISM 0x00651458
class TBuildingView : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TBuildingView)
  virtual ~TBuildingView() override;
  virtual void Close() override;
  virtual void ApplyCityViewSelectionPayloadAndRefreshControls(TCity* city, bool isEmbeddedPage,
                                                               TCityProductionView* productionView,
                                                               short embeddedPageIndex);
  virtual void DoStartup();
  virtual void UpdateFields();
  // Both push the label's own GetFrame rect through CopyRect and invalidate it.
  virtual void SetTextBox(TStaticText* label, short stringGroup, short stringIndex);
  virtual void SetUniversityDialogTextAndRefresh(TStaticText* label, CString text);
  TCity* city;
  TCityProductionView* productionView;
  bool isEmbeddedPage;
  short embeddedPageIndex;

  // Source evidence: unreferenced retained COMDAT in retail.
  TBuildingView() : TNoHilitePicture() {
    this->city = 0;
  }
};

ASSERT_SIZE(TBuildingView, 0xa0);
