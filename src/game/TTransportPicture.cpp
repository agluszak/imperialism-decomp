#include "game/TTransportPicture.h"
#include "game/CRuntimeClass.h"
#include "game/TControl.h"
#include "game/TGreatPower.h"
#include "game/UiRuntimeContext.h"
#include "game/diplomacy_globals.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663160
CRuntimeClass g_pClassDescTTransportPicture = {nullptr, 0, 0, nullptr, nullptr};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00591d90
TTransportPicture* __cdecl CreateTTransportPictureInstance(void) {
  return new TTransportPicture();
}

// FUNCTION: IMPERIALISM 0x00591e50
CRuntimeClass* TTransportPicture::GetRuntimeClass() {
  return &g_pClassDescTTransportPicture;
}

// FUNCTION: IMPERIALISM 0x00591e70
TTransportPicture::TTransportPicture()
    : TPictureResourceEntryBase(), gaugeMetricId90(0x3a), splitValue94(0), splitValue96(0),
      splitLimit98((short)0xffff) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00591ec0
// TTransportPicture::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00591f10
void TTransportPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId >= 100 && commandId <= 0x65) {
    short nationId = g_pUiRuntimeContext->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationId];
    int metricSlot = static_cast<int>(unknown92);
    short metricA = 0;
    short metricB = 0;
    char* nationBytes = reinterpret_cast<char*>(nation);
    if (metricSlot == 0) {
      metricA = *reinterpret_cast<short*>(nationBytes + 0x13e) +
                *reinterpret_cast<short*>(nationBytes + 0x110);
      metricB = *reinterpret_cast<short*>(nationBytes + 0x10e) +
                *reinterpret_cast<short*>(nationBytes + 0x110);
    } else if (metricSlot == 0x13) {
      metricA = *reinterpret_cast<short*>(nationBytes + 0x162) +
                *reinterpret_cast<short*>(nationBytes + 0x164);
      metricB = *reinterpret_cast<short*>(nationBytes + 0x136) +
                *reinterpret_cast<short*>(nationBytes + 0x134);
    } else {
      metricA = *reinterpret_cast<short*>(nationBytes + metricSlot * 2 + 0x13c);
      metricB = *reinterpret_cast<short*>(nationBytes + metricSlot * 2 + 0x10e);
    }
    bool changed = false;
    if (commandId == 100) {
      if (metricA < metricB && *reinterpret_cast<short*>(nationBytes + 0xa6) != metricA) {
        splitValue94 = (short)(metricA + 1);
        changed = true;
      }
    } else if (metricA > 0) {
      splitValue94 = (short)(metricA - 1);
      changed = true;
    }
    if (changed) {
      RefreshControl();
    }
    return;
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005921c0
bool TTransportPicture::IsSelected(short value, bool refreshNow) {
  (void)value;
  (void)refreshNow;
  return false;
}

// FUNCTION: IMPERIALISM 0x00592830
void TTransportPicture::ApplyRectSlot110(RECT* rectBuffer) {
  TPictureResourceEntryBase::ApplyRectSlot110(rectBuffer);
  InvokeSlot13C();
}

TTransportPicture::~TTransportPicture() {}
