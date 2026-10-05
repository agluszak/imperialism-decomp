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
  virtual ~TBuildingView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;     // slot 0x28 0x4c7180
  virtual void
  ApplyCityViewSelectionPayloadAndRefreshControls(TCity* city, bool isEmbeddedPage,
                                                  TCityProductionView* productionView,
                                                  short embeddedPageIndex); // slot 0x74 0x4c6f30
  virtual void DoStartup();                                                 // slot 0x75 0x4c6fd0
  virtual void UpdateFields();                                              // slot 0x76 0x4c6fb0
  // Both push the label's own QueryBounds rect through CopyRect and invalidate it.
  virtual void SetTextBox(TStaticText* label, short stringGroup,
                                                          short stringIndex); // slot 0x77 0x4c70e0
  virtual void SetUniversityDialogTextAndRefresh(TStaticText* label,
                                                 CString text); // slot 0x78 0x4c6ff0
  TCity* city94;
  TCityProductionView* productionView98;
  bool isEmbeddedPage9C;
  unsigned char padding9D;
  short embeddedPageIndex9E;

  // Source evidence: unreferenced retained COMDAT in retail.
  TBuildingView() : TNoHilitePicture() {
    city94 = 0;
  }
};

ASSERT_SIZE(TBuildingView, 0xa0);
