#include "game/TCivReport.h"
#include "game/mfc.h"


// FUNCTION: IMPERIALISM 0x00590b90
TCivReport* __cdecl CreateTCivReportInstance(void) {
  return new TCivReport();
}
IMPLEMENT_DYNCREATE(TCivReport, TPicture)

// FUNCTION: IMPERIALISM 0x00590c30
TCivReport::TCivReport() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00590c60
// TCivReport::`scalar deleting destructor'
TCivReport::~TCivReport() {}

// FUNCTION: IMPERIALISM 0x00590cb0
bool TCivReport::IsSelected(void* reportRecord) {
  (void)reportRecord;
  return false;
}
