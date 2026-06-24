#pragma once

#include "decomp_types.h"

#include "game/TTurnEventPacket.h"

void DispatchCityRedrawInvalidateEvent(short cityId);
void DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation, int mode);
void EmitTurnEvent3Mode18WithActiveNation(void);
