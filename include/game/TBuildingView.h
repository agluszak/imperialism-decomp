#pragma once

#include "compat.h"
#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

class TCity;
class TCityProductionView;

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
  virtual undefined SetUniversityDialogLocalizedTextAndRefresh(int* view, int arg2,
                                                               int arg3); // slot 0x77 0x4c70e0
  virtual undefined SetUniversityDialogTextAndRefresh(int* view,
                                                      CString text); // slot 0x78 0x4c6ff0
  // The +0x94 receiver is a TCity: derived readers land exactly on city stock +0xb6,
  // productionSummary1d8, and the production-order table at +0x1dc.
  TCity* city94;
  // The city-production host: Shipyard UpdateFields calls its slot 0x77 UpdateUnits,
  // and Close clears its 16-entry
  // buildingViewsAC array at +0xac.
  TCityProductionView* productionView98;
  bool isEmbeddedPage9C;
  unsigned char padding9D;
  short embeddedPageIndex9E;

  TBuildingView();
};

ASSERT_SIZE(TBuildingView, 0xa0);
