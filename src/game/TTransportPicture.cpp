// Transport picture wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

char g_vtblTTransportPicture;
char g_pClassDescTTransportPicture;

struct TransportPictureState {
  void* vftable;
  char pad_04[0x8c];
  short gaugeMetricId90;
  short unknown92;
  short splitValue94;
  short splitValue96;
  short splitLimit98;
};

class RuntimeBridge {
public:
  static __inline void ConstructPictureResourceEntryBase(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructPictureResourceEntryBase)(self);
  }

  static __inline void DestructCityDialogSharedBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

} // namespace

// FUNCTION: IMPERIALISM 0x00591D90
TransportPictureState* __cdecl CreateTTransportPictureInstance(void) {
  TransportPictureState* picture =
      reinterpret_cast<TransportPictureState*>(AllocateWithFallbackHandler(0x9c));
  if (picture != 0) {
    RuntimeBridge::ConstructPictureResourceEntryBase(picture);
    picture->vftable = reinterpret_cast<void*>(&g_vtblTTransportPicture);
    picture->gaugeMetricId90 = 0x3a;
    picture->splitValue94 = 0;
    picture->splitValue96 = 0;
    picture->splitLimit98 = (short)0xffff;
  }
  return picture;
}

// FUNCTION: IMPERIALISM 0x00591E50
void* __cdecl GetTTransportPictureClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTransportPicture);
}

// FUNCTION: IMPERIALISM 0x00591E70
TransportPictureState* __fastcall
ConstructTTransportPictureBaseState(TransportPictureState* picture) {
  RuntimeBridge::ConstructPictureResourceEntryBase(picture);
  picture->vftable = reinterpret_cast<void*>(&g_vtblTTransportPicture);
  picture->gaugeMetricId90 = 0x3a;
  picture->splitValue94 = 0;
  picture->splitValue96 = 0;
  picture->splitLimit98 = (short)0xffff;
  return picture;
}

// FUNCTION: IMPERIALISM 0x00591EC0
TransportPictureState* __fastcall
DestructTTransportPictureAndMaybeFree(TransportPictureState* picture, int unusedEdx,
                                      unsigned char freeSelfFlag) {
  (void)unusedEdx;
  RuntimeBridge::DestructCityDialogSharedBaseState(picture);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)picture);
  }
  return picture;
}
