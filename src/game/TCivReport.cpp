#include "game/TCivReport.h"

void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_BuildCivReportNationEntryDetailTextBlock(void);

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

// FUNCTION: IMPERIALISM 0x00590c60
TCivReport* __fastcall DestructTCivReportAndMaybeFree(TCivReport* report, int unusedEdx,
                                                      unsigned char freeSelfFlag) {
  (void)unusedEdx;
  report->~TCivReport();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)report);
  }
  return report;
}

TCivReport::~TCivReport() {}

// FUNCTION: IMPERIALISM 0x00590cb0
void __fastcall BuildCivReportNationEntryDetailTextBlock(TCivReport* context, int unusedEdx,
                                                         void* arg1) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(
      thunk_BuildCivReportNationEntryDetailTextBlock)(context, 0, arg1);
}
