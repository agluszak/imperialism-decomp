#include "game/TTransportPicture.h"
#include "game/TSimMgr.h"
#include "game/mfc.h"
#include "game/TControl.h"
#include "game/TGreatPower.h"
#include "game/TStaticText.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00591d90
// TTransportPicture::CreateObject
// SYNTHETIC: IMPERIALISM 0x00591e50
// TTransportPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTransportPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00591e70
TTransportPicture::TTransportPicture()
    : TPicture(), gaugeMetricId90(0x3a), splitValue94(0), splitValue96(0),
      splitLimit98((short)0xffff) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00591ec0
// TTransportPicture::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00591f10
void TTransportPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId >= 100 && commandId <= 0x65) {
    short nationId = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationId];
    int metricSlot = static_cast<int>(resourceMetricSlot92);
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
void TTransportPicture::Refresh() {
  short total = splitValue96;
  if (total < 1) {
    total = 1;
  }

  // The gauge is 113 pixels wide. The original gives the first remainder pixels one
  // extra pixel so all integer divisions still fill the complete bar.
  float pixelsPerUnit = 113.0f / static_cast<float>(total);
  float remainder = 113.0f - pixelsPerUnit * static_cast<float>(total);
  float markerPosition;
  if (remainder < static_cast<float>(splitValue94)) {
    markerPosition = remainder * (pixelsPerUnit + 1.0f) +
                     (static_cast<float>(splitValue94) - remainder) * pixelsPerUnit;
  } else {
    markerPosition = static_cast<float>(splitValue94) * (pixelsPerUnit + 1.0f);
  }

  CString currentText;
  CString totalText;
  CString gaugeText;
  currentText.Format(g_szDecimalFormat, static_cast<int>(splitValue94));
  totalText.Format(g_szDecimalFormat, static_cast<int>(splitValue96));
  gaugeText = currentText + CString(s_szSpaceSeparator_00695794) + totalText;

  TStaticText* text = static_cast<TStaticText*>(ResolveControlByTag('text'));
  text->AssertValid();
  text->SetTextAndMaybeRefresh(&gaugeText, 1);

  if (resourceMetricSlot92 == 0x16 || resourceMetricSlot92 == 0x15) {
    int multiplier = resourceMetricSlot92 == 0x16 ? 200 : 500;
    CString valueText;
    valueText.Format(g_szDecimalFormat, static_cast<int>(splitValue94) * multiplier);
    TStaticText* value = static_cast<TStaticText*>(ResolveControlByTag('valu'));
    value->AssertValid();
    value->SetTextAndMaybeRefresh(&valueText, 1);
  }

  if (splitLimit98 >= 0) {
    SetState(splitValue94 < splitLimit98 ? 0 : 1, 0);
  }

  if (controlTag != static_cast<int>('tota')) {
    short activeNation = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[activeNation];
    TTransportPicture* totalPicture =
        static_cast<TTransportPicture*>(ownerContext->ResolveControlByTag('tota'));
    totalPicture->AssertValid();
    totalPicture->splitValue94 = nation != 0 ? nation->needsOverCapFlag : 0;
    totalPicture->RefreshControl();
  }

  (void)markerPosition;
  TView::RefreshControl();
}

// FUNCTION: IMPERIALISM 0x00592830
void TTransportPicture::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
  InvokeSlot13C();
}

TTransportPicture::~TTransportPicture() {}
