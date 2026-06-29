#include "game/TTown.h"

#include "game/TSimMgr.h"
#include "game/TStream.h"
#include <string.h>

#include "game/global_data_tables.h"
#include "game/mfc.h"

extern "C" CRuntimeClass PTR_s_TTown_0066d780;

static void SwapAdjacentBytePairs(unsigned char* bytes, int pairCount) {
  int remaining = pairCount;
  while (remaining > 0) {
    unsigned char first = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = first;
    bytes += 2;
    remaining--;
  }
}

// MFC-style GetRuntimeClass (slot 0): returns the class descriptor that precedes
// the vtable at 0x0066d7c8.
IMPLEMENT_DYNCREATE(TTown, TObject)

// Bare vptr-write constructor; all field state comes from InitializeTownMarker.
// FUNCTION: IMPERIALISM 0x005b6c60
TTown::TTown() {}

// FUNCTION: IMPERIALISM 0x005b6cd0
void TTown::InitializeTownMarker(const char* markerName, short regionId, char enabledFlag,
                                 short ownerNation) {
  strcpy(this->name, markerName);
  this->ownerNation1c = ownerNation;
  this->regionId14 = regionId;
  this->enabledFlag4d = enabledFlag;
  this->activeFlag4f = enabledFlag == 0;
  this->flags16[0] = 0;
  this->flags16[1] = 0;
  this->flags16[2] = 0;
  this->flags16[3] = 0;
  this->createdTurnTick1a = g_pLocalizationTable->GetTurnTickSlot3C();
  this->transportLinkedFlag4c = 0;
  memset(this->payload1e, 0, sizeof(this->payload1e));
}

// FUNCTION: IMPERIALISM 0x005b6d70
void TTown::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(name, sizeof(name));
  stream->ReadBytes(&regionId14, 2);
  stream->ReadBytes(flags16, sizeof(flags16));
  stream->ReadBytes(&createdTurnTick1a, 2);
  stream->ReadBytes(&ownerNation1c, 2);
  stream->ReadBytes(payload1e, sizeof(payload1e));
  SwapAdjacentBytePairs(payload1e, 0x17);
  stream->ReadBytes(&transportLinkedFlag4c, 1);
  stream->ReadBytes(&enabledFlag4d, 1);
  stream->ReadBytes(&pad4e, 1);
  stream->ReadByte(&activeFlag4f);
}

// FUNCTION: IMPERIALISM 0x005b6e60
void TTown::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(name, sizeof(name));
  stream->WriteBytesSlot78(&regionId14, 2);
  stream->WriteBytesSlot78(flags16, sizeof(flags16));
  stream->WriteBytesSlot78(&createdTurnTick1a, 2);
  stream->WriteBytesSlot78(&ownerNation1c, 2);
  stream->WriteBytesSlot78(payload1e, sizeof(payload1e));
  stream->WriteBytesSlot78(&transportLinkedFlag4c, 1);
  stream->WriteBytesSlot78(&enabledFlag4d, 1);
  stream->WriteBytesSlot78(&pad4e, 1);
  stream->streamSlot80(activeFlag4f);
}

TTown::~TTown() {}

extern undefined4 HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(void);

// FUNCTION: IMPERIALISM 0x005b7830
char TTown::IsTransportLinkedAndEnabled(void) {
  if (this->enabledFlag4d == 0) {
    return 0;
  }
  char(__cdecl * hasReachableSeaTile)(short) = reinterpret_cast<char(__cdecl*)(short)>(
      HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask);
  if (hasReachableSeaTile(this->regionId14) == 0) {
    return 0;
  }
  return 1;
}
