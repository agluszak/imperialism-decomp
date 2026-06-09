#include "game/trade_quickdraw.h"
#include "game/GameAssert.h"
#include "game/NationState.h"
#include "game/UiRuntimeContext.h"

const char kUSmallViewsCppPath[] = "D:\\Ambit\\Cross\\USmallViews.cpp";

const int kControlTagBar = 0x62617220;
const int kAssertLineMoveBarInitNil = 0x725;

const int kTradeSellPropagationTags[] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

void FailNilPointerInUSmallViews(int line) {
  FailNilPointerWithAssert(kUSmallViewsCppPath, line);
}

int QueryUiScreenModeRaw(UiRuntimeContext* runtimeContext) {
  return runtimeContext->QueryUiScreenModeSlot54();
}

NationState* GetNationStateBySlot(short slotId) {
  NationState** ppNationStates = reinterpret_cast<NationState**>(kAddrGlobalNationStates);
  return ppNationStates[slotId];
}

short QueryNationMetricBySlot(NationState* nationState, short metricSlot) {
  return nationState->QueryNationMetricBySlot78(metricSlot);
}
