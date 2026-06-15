#include "game/TMission.h"

#include "decomp_types.h"
#include "game/CArchive.h"
#include "game/CRuntimeClass.h"

extern "C" {
// TMission RTTI descriptor (slot-0 GetRuntimeClass returns it). Defined in
// global_data_tables.cpp; reccmp pairs by symbol name.
extern CRuntimeClass PTR_s_TMission_00697848;
// Default mission score constant (0.0) loaded by the slot 0x68-0x7C float stubs.
extern float g_MissionDefaultScore_0065a468;
}

undefined4 thunk_CreateMissionObjectByKindAndNodeContext(void);

// Slot 0x07: delete-self via the scalar-deleting destructor (vtable slot 0x04/index 1).
// FUNCTION: IMPERIALISM 0x004798b0
void TMission::DeleteSelfViaScalarDtor() {
  delete this;
}

// Slots 0x08/0x09 are generic, class-independent forwarders shared (linker-folded) with
// other vtables (TZone 0x4798d0, TEventHandler 0x415ce0); no ownership marker — the
// MSVC500 linker folds these identical bodies onto the shared addresses.
void* TMission::InvokeObjectVtableMethod24() {
  return CopyPayloadBuffer();
}
void* TMission::CopyPayloadBuffer() {
  return this;
}

// --- TMission default-mission virtual stubs (concrete missions override) ---
// FUNCTION: IMPERIALISM 0x00534c00
char TMission::ReturnFalseSlot28() {
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c20
int TMission::ReturnZeroSlot2C(int a, int b) {
  (void)a;
  (void)b;
  return 0;
}
// FUNCTION: IMPERIALISM 0x00534c40
void TMission::NoOpSlot30() {}
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
void TMission::InvokeSlots34_38_3C() {
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
}
// FUNCTION: IMPERIALISM 0x00534cf0
void TMission::NoOpSlot44() {}
// FUNCTION: IMPERIALISM 0x00534d10
void* TMission::ReturnArgSlot48(void* arg) {
  return arg;
}
// FUNCTION: IMPERIALISM 0x00534d30
char TMission::ReturnFalseSlot4C(int a, int b, int c) {
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
float TMission::ReturnZeroFloatSlot70() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534e90
float TMission::ReturnZeroFloatSlot7C() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534eb0
float TMission::ReturnZeroFloatSlot78() {
  return g_MissionDefaultScore_0065a468;
}
// FUNCTION: IMPERIALISM 0x00534ed0
void TMission::NoOpSlot84(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534ef0
void TMission::NoOpSlot80(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534f10
void TMission::NoOpSlot8C(int a, int b) {
  (void)a;
  (void)b;
}
// FUNCTION: IMPERIALISM 0x00534f30
void TMission::NoOpSlot88(int a, int b) {
  (void)a;
  (void)b;
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

// FUNCTION: IMPERIALISM 0x00534fb0
CRuntimeClass* TMission::GetRuntimeClass() const {
  return &PTR_s_TMission_00697848;
}

// Factory (0x5350d0). TEMP: forwards to the stub until the concrete mission ctors use
// real inheritance (plan step 4 — switch to a real new-by-kind switch).
void* TMission::CreateByKindAndNodeContext(int sourceNation, int missionKind, int arg2, int arg3,
                                           int arg4) {
  return reinterpret_cast<void*(__cdecl*)(int, int, int, int, int)>(
      thunk_CreateMissionObjectByKindAndNodeContext)(sourceNation, missionKind, arg2, arg3, arg4);
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

// --- slot 0x05/0x06 serializers: TODO plan step 5 (currently own the slot only) ---
// FUNCTION: IMPERIALISM 0x00535820
void TMission::SerializeMissionState(CArchive* archive) {
  (void)archive;
}
// FUNCTION: IMPERIALISM 0x005358a0
void TMission::DeserializeMissionState(CArchive* archive) {
  (void)archive;
}
