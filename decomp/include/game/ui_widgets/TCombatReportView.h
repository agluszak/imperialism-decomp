#pragma once

#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

struct CombatReportUnitRecord {
  char name[20];                 // unit/rank display name
  signed char statusStringIndex; // GetString(0x2717, idx) index for the "(...)" suffix
  unsigned char showMarker;      // gates the fixed 5x5 marker-icon overlay blit
  unsigned char pad16;
  signed char widthParam; // gates + sizes the second icon overlay blit
  int initialStrength;
  int losses;
};
ASSERT_SIZE(CombatReportUnitRecord, 0x20);

struct TCombatReportContext {
  signed char nationIdA; // index into g_apTerrainTypeDescriptorTable
  signed char nationIdB; // index into g_apTerrainTypeDescriptorTable
  unsigned char pad02[2];
  short mapTileIndex; // passed to the active strategic-map view's CenterOn()
  unsigned char pad06[2];
  CombatReportUnitRecord* unitsA;
  CombatReportUnitRecord* unitsB;
};

// VTABLE: IMPERIALISM 0x6678a0
class TCombatReportView : public TPicture {
public:
  virtual ~TCombatReportView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  TCombatReportContext* m_reportContext;
  short reportValue;
  short totalPages;
  short participantAUnitCount;
  short participantBUnitCount;
  short participantBFirstPage;

  TCombatReportView();
  DECLARE_DYNCREATE(TCombatReportView)
  void Draw(RECT* rectBuffer) override;
  virtual void StuffValues(TCombatReportContext* reportContext);
};

ASSERT_SIZE(TCombatReportView, 0xa0);
