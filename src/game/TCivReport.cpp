#include "game/TCivReport.h"
#include "game/mfc.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663130
CRuntimeClass g_pClassDescTCivReport = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00590b90
TCivReport* __cdecl CreateTCivReportInstance(void) {
  return new TCivReport();
}

// FUNCTION: IMPERIALISM 0x00590c10
CRuntimeClass* TCivReport::GetRuntimeClass() const {
  return &g_pClassDescTCivReport;
}

// FUNCTION: IMPERIALISM 0x00590c30
TCivReport::TCivReport() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00590c60
// TCivReport::`scalar deleting destructor'
TCivReport::~TCivReport() {}

// FUNCTION: IMPERIALISM 0x00590cb0
bool TCivReport::IsSelected(short value, bool refreshNow) {
  (void)value;
  (void)refreshNow;
  return false;
}
