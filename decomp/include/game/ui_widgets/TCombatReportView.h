#pragma once

#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

struct CombatReportUnitRecord {
  char name[20];                 // +0x00 unit/rank display name
  signed char statusStringIndex; // +0x14 GetString(0x2717, idx) index for the "(...)" suffix
  unsigned char flagAt15;        // +0x15 gates the fixed 5x5 marker-icon overlay blit
  unsigned char pad16;
  signed char widthParam; // +0x17 gates + sizes the second icon overlay blit
  int fieldAt18;          // +0x18 feeds the first guide-line x position (fieldAt18*3/7 + 7)
  int fieldAt1c;          // feeds the second guide-line x position (fieldAt1c*3/7)
};
ASSERT_SIZE(CombatReportUnitRecord, 0x20);

struct TCombatReportContext {
  signed char nationIdA; // +0x00 index into g_apTerrainTypeDescriptorTable
  signed char nationIdB; // +0x01 index into g_apTerrainTypeDescriptorTable
  unsigned char pad02[2];
  short mapTileIndex; // +0x04 passed to the active strategic-map view's CenterOn()
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
