#include "game/ui_widgets/TCivReport.h"
#include "game/mfc.h"

#include "game/ui_screens/CString.h"

// SYNTHETIC: IMPERIALISM 0x00590b90
// TCivReport::CreateObject
// SYNTHETIC: IMPERIALISM 0x00590c10
// TCivReport::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivReport, TPicture)

// FUNCTION: IMPERIALISM 0x00590c30
TCivReport::TCivReport() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00590c60
// TCivReport::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00590c90
TCivReport::~TCivReport() {}

// PARTIAL PORT of 0x590cb0 (1,652 bytes): the six CString locals the label pass
// builds are transcribed; the label/format body that fills the 'ttl0'/'DLOG' children
// from the civilian order entry is not.
// FUNCTION: IMPERIALISM 0x00590cb0
void TCivReport::PopulateCivilianReportContent(TCivUnit* civilianOrderEntry) {
  (void)civilianOrderEntry;
  CString titleText;
  CString whoText;
  CString whereText;
  CString ordersText;
  CString scratchText;
  CString detailText;
}
