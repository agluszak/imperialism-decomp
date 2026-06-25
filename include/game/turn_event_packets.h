#pragma once

#include "decomp_types.h"

#include "game/TTurnEventPacket.h"

void DispatchCityRedrawInvalidateEvent(short cityId);
void DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation, int mode);
void DispatchTaggedGameStateEvent1F20(int packetTag, int param2, int nationSlotOrMode);
void CreateAndSendTurnEvent13_NationAndNineDwords(int nationSlot, int* payloadDwords);
void CreateAndSendTurnEvent21_ThreeBytes(unsigned char byte0, unsigned char byte1,
                                         unsigned char byte2);
void DispatchTurnEvent1AWithNationActionPayload(short param0, short param1, short param2,
                                                short param3, short param4);
void SetTimeEmitPacketGameFlowTurnId(short* turnTokenField);
void EmitTurnEvent3Mode18WithActiveNation(void);
