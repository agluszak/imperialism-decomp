#pragma once

#include "game/TAmtBar.h"

struct TDocument;

// VTABLE: IMPERIALISM 0x00666ba0
struct TTraderAmtBar : public TradeAmountBarLayout {
  TTraderAmtBar();
  void DoPostCreate(TDocument* document);
  short AdjustForZero(short priorResult, short requestedValue);
  void DrawAmt();
};

extern "C" char g_pClassDescTTraderAmtBar;

TTraderAmtBar* __cdecl CreateTTraderAmtBarInstance(void);
void* __cdecl GetTTraderAmtBarClassNamePointer(void);
TTraderAmtBar* __fastcall ConstructTTraderAmtBarBaseState(TTraderAmtBar* amountBar);
TTraderAmtBar* __fastcall DestructTTraderAmtBarMaybeFree(TTraderAmtBar* amountBar,
                                                         int unusedEdx,
                                                         unsigned char freeSelfFlag);
