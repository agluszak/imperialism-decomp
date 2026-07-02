#include "game/TMission.h"
#include "game/global_data_tables.h"

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/mfc.h"
#include "game/TStream.h"

// TMission RTTI descriptor (slot-0 GetRuntimeClass returns it). Defined in
// global_data_tables.cpp; reccmp pairs by symbol name.
extern "C" CRuntimeClass PTR_s_TMission_00697848;

undefined4 CreateMissionObjectByKindAndNodeContext(void);

// --- TMission default-mission virtual stubs (concrete missions override) ---
// FUNCTION: IMPERIALISM 0x00534c00
char TMission::ReturnFalseSlot28() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c20
int TMission::ReturnZeroSlot2C(int* outBuffer, int unused) {
  (void)outBuffer;
  (void)unused;
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c40
void TMission::Call30() {}

// FUNCTION: IMPERIALISM 0x00534c60
void TMission::SetStateByte8To2() {
  state08 = 2;
}
// FUNCTION: IMPERIALISM 0x00534c80
void TMission::ResetValue0CToZero() {
  value0c = 0;
}
// FUNCTION: IMPERIALISM 0x00534ca0
void TMission::NoOpSlot3C() {}
// FUNCTION: IMPERIALISM 0x00534cc0
void TMission::RefreshSlot40() {
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
}
// FUNCTION: IMPERIALISM 0x00534cf0
void TMission::MissionSlot44() {}
// FUNCTION: IMPERIALISM 0x00534d10
TMission* TMission::GetReplacementSlot48() {
  return this;
}
// FUNCTION: IMPERIALISM 0x00534d30
char TMission::MatchesMissionKeySlot4C(int a, int b, int c) {
  (void)a;
  (void)b;
  (void)c;
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534d50
char TMission::ReturnFalseSlot50() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534d70
char TMission::ReturnFalseSlot54() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534d90
int TMission::ReturnZeroSlot58() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534db0
int TMission::ReturnZeroSlot5C() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534dd0
char TMission::ReturnFalseSlot60() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534df0
char TMission::ReturnFalseSlot64() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534e10
float TMission::ReturnZeroFloatSlot68() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e30
float TMission::ReturnZeroFloatSlot6C() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e50
float TMission::ReturnZeroFloatSlot74() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e70
float TMission::ReturnZeroFloatSlot70(TMilitaryUnit* candidateUnit) {
  (void)candidateUnit;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e90
float TMission::ReturnZeroFloatSlot7C() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534eb0
float TMission::ReturnZeroFloatSlot78(TMilitaryUnit* candidateUnit, float* referenceVector) {
  (void)candidateUnit;
  (void)referenceVector;
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534ed0
void TMission::NoOpSlot84(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534ef0
void TMission::NoOpSlot80(TMilitaryUnit* unit, int notify) {
  (void)unit;
  (void)notify;
}
// FUNCTION: IMPERIALISM 0x00534f10
void TMission::NoOpSlot8C(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534f30
void TMission::NoOpSlot88(TMilitaryUnit* unit, int unused) {
  (void)unit;
  (void)unused;
}
// FUNCTION: IMPERIALISM 0x00534f50
void TMission::NoOpSlot90(int a) {
  (void)a;
}
// FUNCTION: IMPERIALISM 0x00534f70
void TMission::SetFlag10FromArgSlot94(unsigned char value) {
  flag10 = value;
}
// FUNCTION: IMPERIALISM 0x00534f90
char TMission::ReturnFalseSlot98() {
  return 0;
}

void TMission::AssertValid(CArchive* archive) const {
  (void)archive;
}
// SYNTHETIC: IMPERIALISM 0x00534fb0
// TMission::GetRuntimeClass

// SYNTHETIC: IMPERIALISM 0x00534bc0
// TMission::CreateObject

IMPLEMENT_SERIAL(TMission, TObject, 1)

void* TMission::CreateByKindAndNodeContext(int sourceNation, int missionKind, int arg2,
                                           TZone* portZoneContext, int arg4) {
  return reinterpret_cast<void*(__cdecl*)(int, int, int, int, int)>(
      CreateMissionObjectByKindAndNodeContext)(sourceNation, missionKind, arg2,
                                               reinterpret_cast<int>(portZoneContext), arg4);
}

// FUNCTION: IMPERIALISM 0x00535020
TMission::TMission() {
  state08 = 2;
  value0c = 0;
  marker11 = 0xff;
}

// SYNTHETIC: IMPERIALISM 0x00535050
// TMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00535080
TMission::~TMission() {}

// --- slot 0x05/0x06 serializers (TStream* fast-path; same vtable offsets as WriteTo/ReadFrom) ---
// FUNCTION: IMPERIALISM 0x00535820
void TMission::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  char* raw = reinterpret_cast<char*>(this);
  stream->WriteBytesSlot78(raw + 0x04, 2);
  stream->WriteBytesSlot78(raw + 0x08, 1);
  stream->WriteBytesSlot78(raw + 0x0c, 4);
  stream->WriteBytesSlot78(raw + 0x10, 1);
  stream->WriteBytesSlot78(raw + 0x06, 2);
  stream->WriteBytesSlot78(raw + 0x11, 1);
}

// FUNCTION: IMPERIALISM 0x005358a0
void TMission::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&nationId04, 2);
  stream->ReadBytes(&state08, 1);
  stream->ReadBytes(&value0c, 4);
  stream->ReadBytes(&flag10, 1);
  if (g_nSaveFormatVersion < 0x10) {
    pathMarker06 = static_cast<short>(0xffff);
  } else {
    stream->ReadBytes(&pathMarker06, 2);
  }
  if (g_nSaveFormatVersion < 9) {
    RefreshSlot40();
    return;
  }
  stream->ReadBytes(&marker11, 1);
}
