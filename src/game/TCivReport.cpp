// Civ report wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

char g_vtblTCivReport;
char g_pClassDescTCivReport;

struct CivReportState {
  void *vftable;
  char pad_04[0x8c];
};

class RuntimeBridge {
public:
  static __inline void ConstructPictureResourceEntryBase(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void DestructCityDialogSharedBaseState(void *self)
  {
    reinterpret_cast<void (__fastcall *)(void *)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

}  // namespace

// FUNCTION: IMPERIALISM 0x00590B90
CivReportState *__cdecl CreateTCivReportInstance(void)
{
  CivReportState *report =
      reinterpret_cast<CivReportState *>(AllocateWithFallbackHandler(0x90));
  if (report != 0) {
    RuntimeBridge::ConstructPictureResourceEntryBase(report);
    report->vftable = reinterpret_cast<void *>(&g_vtblTCivReport);
  }
  return report;
}


// FUNCTION: IMPERIALISM 0x00590C10
void *__cdecl GetTCivReportClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCivReport);
}


// FUNCTION: IMPERIALISM 0x00590C30
CivReportState *__fastcall ConstructTCivReportBaseState(CivReportState *report)
{
  RuntimeBridge::ConstructPictureResourceEntryBase(report);
  report->vftable = reinterpret_cast<void *>(&g_vtblTCivReport);
  return report;
}


// FUNCTION: IMPERIALISM 0x00590C60
CivReportState *__fastcall DestructTCivReportAndMaybeFree(
    CivReportState *report, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  RuntimeBridge::DestructCityDialogSharedBaseState(report);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)report);
  }
  return report;
}
