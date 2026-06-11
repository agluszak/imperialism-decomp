#include "game/TCivReport.h"

namespace {

// GLOBAL: IMPERIALISM 0x663130
char g_pClassDescTCivReport;

} // namespace

// FUNCTION: IMPERIALISM 0x00590b90
TCivReport* __cdecl CreateTCivReportInstance(void) {
  return new TCivReport();
}

// FUNCTION: IMPERIALISM 0x00590c10
void* __cdecl GetTCivReportClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCivReport);
}

// FUNCTION: IMPERIALISM 0x00590c30
TCivReport::TCivReport() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00590c60
// TCivReport::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00590cb0
void __fastcall BuildCivReportNationEntryDetailTextBlock(TCivReport* context, int unusedEdx,
                                                         void* arg1) {
  (void)unusedEdx;
  (void)context;
  (void)arg1;
}
