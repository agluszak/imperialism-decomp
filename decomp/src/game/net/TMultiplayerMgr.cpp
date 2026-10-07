#include "game/nation_domain_types.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_tags_screens.h"
#include "game/ui_tags_widgets.h"
#include "game/resource_domain_types.h"
#include "game/civilian_domain_types.h"
#include "game/military_domain_types.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/net/TMadnessButton.h"
#include "game/ui_tags_map.h"
#include <stdlib.h>
#include "game/tactical/TArmyBattle.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TPtrList.h"
#include "game/city/TTown.h"

#include <string.h>
#include <time.h>

#include "decomp_types.h"
#include "game/core/CString.h"
#include "game/assets/TAssetMgr.h"
#include "game/military/mapped_flavor_text.h"
#include "game/military/NetMessage.h"
#include "game/multiplayer_packets.h"
#include "game/nation/TLandSaleEvent.h"
#include "game/nation/TTurnStartEvent.h"
#include "game/ImperialismApp.h"

struct TurnEvent2CPacket : TimelyNetMessagePrefix {
  short nationSlot;
  unsigned char pad1e[2];
  int specialResourceTradeBalance;
  int aidAllocationTotal;
  unsigned char pad28[6];
  short militaryRecruitCountByKind[kMilitaryUnitKindCount];
  short civilianRecruitCountByKind[kCivilianUnitKindCount];
  short orderCountByType[kIndustryActionSlotCount];
  int cityRollingItemProductionScore;
  short cityFieldB4;
  short cityStock[kResourceKindCount];
  short productionOrderTable[0x10];
  short productionAccum[0x10];
  short populationGrowthPenaltyTicks;
  unsigned char pad10e[2];
  int orderAccumulatedValues[0x17];
  short popFieldAt8;
  unsigned char pad16e[2];
  float popFieldAtC; // mirrors TPopulationMgr::populationCountFloat
  short popStockLevel;
  short popExtraAt1e;
  short popFieldAt20;
  short popBucketWords[9]; // baseline/production/pendingDelta valueAt4/6/8
};

struct TurnEvent19Packet : TimelyNetMessagePrefix {
  short nationSlot;
  short transportCapacity;
  short orderCountByType[kIndustryActionSlotCount];
  short externalStateByTarget[0x17];
  short metricBySlot7C[0x11];
  short diplomacyPolicyByNation[kNationSlotCount];
  short diplomacyGrantByNation[kNationSlotCount];
  short tradePolicyByNation[kNationSlotCount];
  unsigned char pad116[2];
};

// Turn-event-0x15 payload: the sender nation's full diplomacy need-state block.
struct TurnEvent15Packet : TimelyMessageHeader {
  short nationSlot;
  unsigned char pad1a[2];
  int treasuryValue;
  int grantTotalCost;
  short needCurrentByType[kResourceKindCount];
  short needTargetByType[kResourceKindCount];
  short relationDeltaCurrent[0x17];
  short purchasedItemsByResource[kResourceKindCount];
  short itemPotentials[kResourceKindCount];
  unsigned char pad10a[2];
  int aidAllocationMatrix[0x170];
  int budgetPoolBase;
  int budgetPoolDelta;
  int diplomacyBudgetBase;
  signed char escalationCounter;
  unsigned char pad6d9[3];
  int pendingCommitmentCost;
  signed char pressureCounter;
  unsigned char pad6e1[3];
};
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TMinor.h"
#include "game/city/TCity.h"
#include "game/military/TCancelGameOptionsCommand.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/core/THandleStream.h"
#include "game/core/TCountingStream.h"
#include "game/ui_core/CIterator.h"
#include "game/city/TPopulationMgr.h"
#include "game/city/TProductionOrder.h"
#include "game/net/TNetMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/gfx/TResourceMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/navy/TOcean.h"
#include "game/map/TZone.h"
#include "game/military_ui/TNextDiplomationCommand.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_screens/TMapPreviewView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/net_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/net/TLoungeDialog.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_core/TPicture.h"
#include "game/net/TPoseMessageDialog.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/ui_screens/TTextPictureButton.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include <cstdlib>
#include <cstring>

// FUNCTION: IMPERIALISM 0x005427a0
TMultiplayerSlotHandle::TMultiplayerSlotHandle() : allocatedData(0), tagOrSize(0) {}

// FUNCTION: IMPERIALISM 0x005427c0
TMultiplayerSlotHandle::~TMultiplayerSlotHandle() {
  if (allocatedData != 0) {
    delete allocatedData;
  }
}

struct TurnEvent12Packet : TimelyMessageHeader {
  short shortA;
  short shortB;
};

struct TurnEventCKickMessagePacket : TimelyMessageHeader {
  char messageText[0x100];
  unsigned char targetNationBitmask; // 1 << slot per addressed nation
  signed char kickerNationId;        // +0x119 + 1 = no specific kicker
  unsigned char pad11a[2];
};

// Event-0x11 masked byte/word/dword poke into one of the two global map tables.
struct TurnEvent11MapPokePacket : TimelyMessageHeader {
  signed char pokeWidthCode; // 1 byte / 2 word / 4 dword
  unsigned char pad19[3];
  int bufferSelector; // 0 terrainStateTable, 1 cityScoreTable, else null base
  int byteOffset;     // raw byte offset into the selected table
  short pokeValue;
  short pokeMask;
};

struct TurnEvent20TreatyNewsPacket : TimelyMessageHeader {
  short eventKind; // +0x18 InterNationEventKind
  signed char nationA;
  signed char nationB;
};
ASSERT_SIZE(TurnEvent20TreatyNewsPacket, 0x1c);
struct TurnEvent21ShortageNewsPacket : TimelyMessageHeader {
  signed char subjectNation;
  signed char affectedNation;
  signed char relatedNation;
  unsigned char pad1b;
};
ASSERT_SIZE(TurnEvent21ShortageNewsPacket, 0x1c);
struct TurnEvent22MiscNewsPacket : TimelyMessageHeader {
  signed char nationSlotOrAll;
  unsigned char pad19;
  short storyCode;
};
ASSERT_SIZE(TurnEvent22MiscNewsPacket, 0x1c);

// Event-0x1A nation action + per-nation counterA2 words.
struct TurnEvent1ANationActionPacket : TimelyNetMessagePrefix {
  short respondingNation;
  short offeringNation;
  short proposedAmount;
  short maxAmount;
  short commodityType;
  short counterA2BySlot[7];
};

// Event-0x1B one tracked-slot entry.
struct TurnEvent1BDealBookEntryPacket : TimelyNetMessagePrefix {
  short nationSlot;
  short trackedKind;
  short targetNation;
  short trackedValue;
  short trackedSlotIndex;
  unsigned char pad26[2];
  int trackedPayload;
};

// Event-0x1C trade deal result.
struct TurnEvent1CDealResultPacket : TimelyNetMessagePrefix {
  short sourceNation;
  short targetNation;
  short maximumAmount;
  short commodityType;
  short amount;
  short shortfallFlag;
};
ASSERT_SIZE(TurnEvent1CDealResultPacket, 0x28);

// Event-0x1E diplomacy relation action.
struct TurnEvent1EDiplomacyActionPacket : TimelyNetMessagePrefix {
  signed char nation;
  signed char nationA1D;
  signed char nationB1E;
  char actionCode;      // +0x1f - 'a' or 'i'
  unsigned char flag20; // role-swap selector
  unsigned char flag21; // gate for the slot-0x284 paths
  unsigned char pad22[2];
};

// Event-0x24 one city-score record (receive side: the 0xa8-byte record is contiguous).
struct TurnEvent24CityRecordPacket : TimelyNetMessagePrefix {
  short cityRecordIndex;
  unsigned char pad1e[2];
  Province record;
};
ASSERT_SIZE(TurnEvent24CityRecordPacket, 0xc8);
ASSERT_OFFSET(TurnEvent24CityRecordPacket, record, 0x20);

// Event-0x27 join-empire dispatch.
struct TurnEvent27JoinEmpirePacket : TimelyMessageHeader {
  int terrainSlot; // index into g_apTerrainTypeDescriptorTable
  int targetNationSlot;
  int mode;
};

// Events 0x29/0x2A tactical battle commands by fourcc tag.
struct TacticalCommandPacket : TimelyMessageHeader {
  int commandTag; // +0x18 'sele'/'move'/'mine'/'digg'/'depl'/'raly' (0x29), 'fire' (0x2a)
  int unitId;     // resolved via SeekLinkedListCursorByNestedId
  int arg20;
  int arg24;
  int arg28; // +0x28 ('fire' only)
  int arg2C; // total 0x30
};

// FUNCTION: IMPERIALISM 0x00543280
void TMultiplayerMgr::HandleTurnResumeStateTelemetry() {
  bool hosting = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
  if (hosting) {
    for (int slot = 0; slot < 7; ++slot) {
      TGreatPower* nation = g_apNationStates[slot];
      if (nation == 0 || !nation->IsClient()) {
        pendingNationBitmask &= ~(1 << slot);
      }
    }
    pendingNationBitmask &= ~(1 << g_pSimMgr->GetPlayerCountry());
    bool stillHosting = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (stillHosting) {
      TurnEvent1PendingMaskPacket packet;
      packet.InitializeEmitEventHeaderWithActiveNation();
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.eventCode = 1;
      packet.toNetworkId = 0;
      packet.pendingMask = pendingNationBitmask;
      packet.messageLength = 0;
      packet.messageLength = 0x1c;
      packet.toNetworkId = 0;
      g_pNetMgr->Send(&packet, false);
      if (pendingNationBitmask == 0 && syncPhase != kGamePhaseNone) {
        HandleDiplomacyTurnEventPacketByCode();
      }
    }
  } else {
    switch (syncPhase) {
    case kGamePhaseStartGame: {
      CString cityName;
      SendNationStateMessage(g_pSimMgr->GetPlayerCountry(), -1);
      SendCityStateMessage(g_pSimMgr->GetPlayerCountry(), -1);
      TurnEventACityAnnouncePacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.eventCode = 0xa;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x44;
      packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
      int nationId = static_cast<char>(g_pSimMgr->GetPlayerCountry());
      packet.nationId = nationId;
      packet.homeTile = static_cast<short>(g_apTerrainTypeDescriptorTable[nationId]->homeTileIndex);
      int cityRecordIndex = g_apTerrainTypeDescriptorTable[nationId]->GetCapitolProvince();
      g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
      strncpy(packet.cityName, cityName, 0x21);
      g_pNetMgr->Send(&packet, false);
      break;
    }
    case kGamePhaseEndTurn: {
      SendStreamMessage(0x2e, -1, g_pSimMgr->GetPlayerCountry());
      SendStreamMessage(0x2f, -1, g_pSimMgr->GetPlayerCountry());
      SendStreamMessage(0x30, -1, g_pSimMgr->GetPlayerCountry());
      for (int slot = 0; slot < kNationSlotCount; ++slot) {
        TMinor* minor = g_apSecondaryNationStateSlots[slot];
        if (minor != 0) {
          minor->InitializeTradeStatus();
        }
      }
      g_apNationStates[g_pSimMgr->GetPlayerCountry()]->InitializeTradeStatus();
      SendNationStateMessage(g_pSimMgr->GetPlayerCountry(), -1);
      SendCityStateMessage(g_pSimMgr->GetPlayerCountry(), -1);
      TurnEventFResumeAckPacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.eventCode = 0xf;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
      packet.nationSlot = g_pSimMgr->GetPlayerCountry();
      g_pNetMgr->Send(&packet, false);
      break;
    }
    case kGamePhaseCityAndTransport: {
      SendCityStateMessage(g_pSimMgr->GetPlayerCountry(), -1);
      TurnEventFResumeAckPacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.eventCode = 0xf;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
      packet.nationSlot = g_pSimMgr->GetPlayerCountry();
      g_pNetMgr->Send(&packet, false);
      break;
    }
    case kGamePhaseCombat:
    case kGamePhaseProduction: {
      TurnEventFResumeAckPacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.eventCode = 0xf;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = -1;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
      packet.nationSlot = g_pSimMgr->GetPlayerCountry();
      g_pNetMgr->Send(&packet, false);
      break;
    }
    default:
      break;
    }
  }

  int readySlot = g_pSimMgr->GetPlayerCountry();
  if (readySlot == -1) {
    readySlot = static_cast<signed char>(activeNationTagIndex);
  }
  nationStatusTags[readySlot] = kSessionTagRedy; // 'redy'
  NationStatusEvent25Packet packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.eventCode = 0x25;
  packet.messageLength = 0;
  for (int i = 0; i < 7; ++i) {
    packet.statusTags[i] = kSessionTagUnkn; // 'unkn'
  }
  packet.messageLength = 0x34;
  packet.toNetworkId = 0;
  packet.statusTags[readySlot] = kSessionTagRedy; // 'redy'
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x00543910
void TMultiplayerMgr::HandleDiplomacyTurnEventPacketByCode() {
  switch (syncPhase) {
  case kGamePhaseStartGame: {
    TurnEvent2SyncPacket* syncPacket =
        g_pDiplomacyTurnStateManager
            ->BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
    syncPacket->toNetworkId = 0;
    g_pNetMgr->Send(syncPacket, false);
    delete[] static_cast<unsigned char*>(static_cast<void*>(syncPacket));
    RecalcPlayerName(-1);

    {
      TurnEventBNationDirectoryPacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.eventCode = 0xb;
      packet.toNetworkId = 0;
      packet.toNetworkId = 0;
      packet.messageLength = 0;
      packet.messageLength = 0x668;
      packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
      for (int slot = 0; slot < kNationSlotCount; ++slot) {
        packet.homeTileBySlot[slot] =
            static_cast<short>(g_apTerrainTypeDescriptorTable[slot]->homeTileIndex);
        int cityRecordIndex = g_apTerrainTypeDescriptorTable[slot]->GetCapitolProvince();
        CString cityName;
        g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
        strncpy(packet.cityNameBySlot[slot], cityName, 0x21);
        CString nationName;
        g_apTerrainTypeDescriptorTable[slot]->AssignSharedStringFromDescriptorNameOrDefault(
            &nationName);
        strncpy(packet.nationNameBySlot[slot], nationName, 0x21);
        TZone* portZone = g_pActiveMapOrderContext->GetPortZone(static_cast<short>(slot));
        packet.portZoneOrdinalBySlot[slot] = portZone->GetContextOrdinalOrInvalid();
      }
      g_pNetMgr->Send(&packet, false);
    }

    for (int capitalSlot = 0; capitalSlot < 7; ++capitalSlot) {
      int homeTile = g_apTerrainTypeDescriptorTable[capitalSlot]->homeTileIndex;
      short neighborTiles[7];
      TMapMgr::GetNeighborTileIDArray(static_cast<short>(homeTile), neighborTiles,
                                      g_pGlobalMapState->hexNeighborWrapHorizontally);
      neighborTiles[6] = static_cast<short>(homeTile);
      for (int k = 0; k < 7; ++k) {
        short tileIndex = neighborTiles[k];
        if (tileIndex != -1) {
          TurnEvent23TileStatePacket packet;
          packet.messageTag = kControlTagTime;
          packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
          packet.eventCode = 0;
          packet.fromNetworkId = 0;
          packet.eventCode = 0x23;
          packet.toNetworkId = 0;
          packet.toNetworkId = 0;
          packet.messageLength = 0;
          packet.messageLength = 0x44;
          packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
          packet.tileIndex = tileIndex;
          packet.record = g_pGlobalMapState->terrainStateTable[tileIndex];
          g_pNetMgr->Send(&packet, false);
        }
      }
      short cityRecordIndex =
          static_cast<short>(g_apTerrainTypeDescriptorTable[capitalSlot]->GetCapitolProvince());
      TurnEvent24CityRecordPacket packet;
      packet.InitializeEmitEventHeaderWithActiveNation();
      packet.eventCode = 0;
      packet.eventCode = 0x24;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.toNetworkId = 0;
      packet.messageLength = 0;
      packet.messageLength = 0xc8;
      packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
      packet.cityRecordIndex = cityRecordIndex;
      packet.record = g_pGlobalMapState->cityScoreTable[cityRecordIndex];
      g_pNetMgr->Send(&packet, false);
    }

    SendStreamMessage(0x2e, -2, -1);
    for (int descriptorSlot = 0; descriptorSlot < kNationSlotCount; ++descriptorSlot) {
      if (g_apTerrainTypeDescriptorTable[descriptorSlot] != 0) {
        SendStreamMessage(0x2f, -2, descriptorSlot);
      }
    }
    SendStreamMessage(0x30, -2, -1);

    for (int stateSlot = 0; stateSlot < 7; ++stateSlot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(stateSlot))) {
        SendNationStateMessage(static_cast<short>(stateSlot), -2);
        SendCityStateMessage(stateSlot, -2);
      }
    }
    for (short minorSlot = 7; minorSlot < kNationSlotCount; ++minorSlot) {
      if (g_pSimMgr->ReallyInTheGame(minorSlot)) {
        TurnEvent2DMinorNeedPacket packet;
        packet.InitializeEmitEventHeaderWithActiveNation();
        packet.eventCode = 0;
        packet.eventCode = 0x2d;
        packet.fromNetworkId = 0;
        packet.toNetworkId = 0;
        packet.toNetworkId = -1;
        packet.messageLength = 0;
        packet.messageLength = 0x4c;
        packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
        packet.DestinateTo(-2);
        packet.nationSlot = minorSlot;
        for (short j = 0; j < 0x17; ++j) {
          packet.tradePolicyByNation[j] =
              g_apSecondaryNationStateSlots[minorSlot]->tradePolicyByNation[j];
        }
        g_pNetMgr->Send(&packet, false);
      }
    }

    RecalcPlayerName(-1);
    EmitTurnEvent3Mode18WithActiveNation();
    break;
  }

  case kGamePhaseEndTurn: {
    bool allReachable = g_pNetMgr->Ping() == 0;
    if (allReachable) {
      SaveGameWithModeAndOptionalLabel(0xa2, 0);
    }
    TurnEvent18DiplomacyArraysPacket packet;
    packet.messageTag = kControlTagTime;
    packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
    packet.eventCode = 0;
    packet.eventCode = 0x18;
    packet.fromNetworkId = 0;
    packet.toNetworkId = 0;
    packet.toNetworkId = 0;
    packet.messageLength = 0;
    packet.messageLength = 0x3e4;
    packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
    for (int slot = 0; slot < 7; ++slot) {
      TGreatPower* nation = g_apNationStates[slot];
      if (nation != 0) {
        for (int j = 0; j < 0x17; ++j) {
          packet.diplomacyPolicyByNation[slot][j] = nation->diplomacyPolicyByNation[j];
          packet.diplomacyGrantByNation[slot][j] = nation->diplomacyGrantByNation[j];
          packet.tradePolicyByNation[slot][j] = nation->tradePolicyByNation[j];
        }
      }
    }
    g_pNetMgr->Send(&packet, false);
    g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    EmitTurnEvent3Mode18WithActiveNation();
    break;
  }

  case kGamePhaseDiplomacy: {
    TNextDiplomationCommand* command = new TNextDiplomationCommand();
    command->PostThyself();
    return;
  }

  case kGamePhaseCityAndTransport: {
    for (int stateSlot = 0; stateSlot < 7; ++stateSlot) {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(stateSlot))) {
        SendNationStateMessage(static_cast<short>(stateSlot), -2);
        SendCityStateMessage(stateSlot, -2);
      }
    }
    for (short minorSlot = 7; minorSlot < kNationSlotCount; ++minorSlot) {
      if (g_pSimMgr->ReallyInTheGame(minorSlot)) {
        TurnEvent2DMinorNeedPacket packet;
        packet.InitializeEmitEventHeaderWithActiveNation();
        packet.eventCode = 0;
        packet.eventCode = 0x2d;
        packet.fromNetworkId = 0;
        packet.toNetworkId = 0;
        packet.toNetworkId = -1;
        packet.messageLength = 0;
        packet.messageLength = 0x4c;
        packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
        packet.toNetworkId = 0;
        packet.nationSlot = minorSlot;
        for (short j = 0; j < 0x17; ++j) {
          packet.tradePolicyByNation[j] =
              g_apSecondaryNationStateSlots[minorSlot]->tradePolicyByNation[j];
        }
        g_pNetMgr->Send(&packet, false);
      }
    }
    EmitTurnEvent3Mode18WithActiveNation();
    break;
  }

  case kGamePhaseCombat:
    EmitTurnEvent3Mode18WithActiveNation();
    break;

  case kGamePhaseProduction: {
    SendStreamMessage(0x2e, -2, -1);
    for (int descriptorSlot = 0; descriptorSlot < kNationSlotCount; ++descriptorSlot) {
      if (g_apTerrainTypeDescriptorTable[descriptorSlot] != 0) {
        SendStreamMessage(0x2f, -2, descriptorSlot);
      }
    }
    SendStreamMessage(0x30, -2, -1);

    TurnEvent2SyncPacket* syncPacket =
        g_pDiplomacyTurnStateManager
            ->BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
    syncPacket->toNetworkId = 0;
    g_pNetMgr->Send(syncPacket, false);
    delete[] static_cast<unsigned char*>(static_cast<void*>(syncPacket));

    SendStreamObject(kControlTagArmy, static_cast<TObject*>(g_pMapContextActionManager), -2);

    for (int snapshotSlot = 0; snapshotSlot < 7; ++snapshotSlot) {
      TGreatPower* nation = g_apNationStates[snapshotSlot];
      if (nation != 0 && nation->IsRemote()) {
        SendBankStatement(false, snapshotSlot);
      }
    }
    EmitTurnEvent3Mode18WithActiveNation();
    break;
  }

  default:
    EmitTurnEvent3Mode18WithActiveNation();
    break;
  }
}

IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY
// FUNCTION: IMPERIALISM 0x00545940
bool TMultiplayerMgr::ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet) {
  TurnEvent1PendingMaskPacket pendingMaskPacket;
  switch (packet->eventCode) {
  case 0xf: {
    TurnEventFResumeAckPacket* ack = static_cast<TurnEventFResumeAckPacket*>(packet);
    pendingNationBitmask &= ~(1 << static_cast<char>(ack->nationSlot));
    bool hosting = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (!hosting) {
      return true;
    }
    pendingMaskPacket.InitializeEmitEventHeaderWithActiveNation();
    pendingMaskPacket.eventCode = 0;
    pendingMaskPacket.fromNetworkId = 0;
    pendingMaskPacket.eventCode = 1;
    pendingMaskPacket.toNetworkId = 0;
    pendingMaskPacket.pendingMask = pendingNationBitmask;
    pendingMaskPacket.messageLength = 0;
    pendingMaskPacket.messageLength = 0x1c;
    pendingMaskPacket.toNetworkId = 0;
    g_pNetMgr->Send(&pendingMaskPacket, false);
    if (pendingNationBitmask == 0 && syncPhase != kGamePhaseNone) {
      HandleDiplomacyTurnEventPacketByCode();
      return true;
    }
    break;
  }
  case 0xa: {
    // A resuming nation announces its home region and city name.
    TurnEventACityAnnouncePacket* announce = static_cast<TurnEventACityAnnouncePacket*>(packet);
    if (g_pSimMgr->scenarioMapIndexPlusOne == 0) {
      int announcedNation = static_cast<char>(announce->nationId);
      g_pGlobalMapState->PlaceCity(announce->homeTile, static_cast<char>(announcedNation));
      g_apNationStates[announcedNation]->PlaceCity(announce->homeTile, announce->cityName);
    }
    pendingNationBitmask &= ~(1 << static_cast<char>(announce->nationId));
    bool hostingA = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (!hostingA) {
      return true;
    }
    pendingMaskPacket.InitializeEmitEventHeaderWithActiveNation();
    pendingMaskPacket.eventCode = 0;
    pendingMaskPacket.fromNetworkId = 0;
    pendingMaskPacket.eventCode = 1;
    pendingMaskPacket.toNetworkId = 0;
    pendingMaskPacket.pendingMask = pendingNationBitmask;
    pendingMaskPacket.messageLength = 0;
    pendingMaskPacket.messageLength = 0x1c;
    pendingMaskPacket.toNetworkId = 0;
    g_pNetMgr->Send(&pendingMaskPacket, false);
    if (pendingNationBitmask == 0 && syncPhase != kGamePhaseNone) {
      HandleDiplomacyTurnEventPacketByCode();
      return true;
    }
    break;
  }
  case 0xb: {
    TurnEventBNationDirectoryPacket* directory =
        static_cast<TurnEventBNationDirectoryPacket*>(packet);
    for (int dirSlot = 0; dirSlot < kNationSlotCount; ++dirSlot) {
      if (dirSlot != g_pSimMgr->GetPlayerCountry() &&
          g_apTerrainTypeDescriptorTable[dirSlot]->IsRemote()) {
        g_apTerrainTypeDescriptorTable[dirSlot]->PlopDownCity(directory->homeTileBySlot[dirSlot],
                                                              directory->cityNameBySlot[dirSlot]);
        {
          CString nationName(directory->nationNameBySlot[dirSlot]);
          g_apTerrainTypeDescriptorTable[dirSlot]->SetNationDisplayNameAndLocalizationSlotRef(
              nationName);
        }
        {
          CString nationName2(directory->nationNameBySlot[dirSlot]);
          g_apTerrainTypeDescriptorTable[dirSlot]->identitySharedString1 = nationName2;
        }
        if (g_pSimMgr->scenarioMapIndexPlusOne == 0) {
          g_pGlobalMapState->PlaceCity(directory->homeTileBySlot[dirSlot],
                                       static_cast<short>(dirSlot));
        }
      }
      TZone* portZone = g_pActiveMapOrderContext->GetPortZone(static_cast<short>(dirSlot));
      portZone->contextOrdinal = directory->portZoneOrdinalBySlot[dirSlot];
    }
    RecalcPlayerName(-1);
    break;
  }
  case 8: {
    TurnEvent8NameAnnouncePacket* announce8 = static_cast<TurnEvent8NameAnnouncePacket*>(packet);
    int announceSlot = announce8->nationSlot;
    if (announceSlot == -1) {
      // Faithful out-of-bounds quirk: slot -1 reads the dword before nationSessionIds.
      g_pNetMgr->NotifyIfNationMatchesSessionActiveNation(nationSessionIds[announceSlot]);
    } else if (nationSessionIds[announceSlot] != 0) {
      int fromId = announce8->fromNetworkId;
      if (nationSessionIds[announceSlot] == fromId) {
        LobbyChatEvent9Packet echo;
        echo.InitializeEmitEventHeaderWithActiveNation();
        echo.sessionId = fromId;
        echo.eventCode = 0;
        echo.fromNetworkId = 0;
        echo.toNetworkId = 0;
        echo.messageLength = 0;
        echo.toNetworkId = 0;
        echo.messageLength = 0x64;
        echo.eventCode = 9;
        echo.nationSlot = static_cast<unsigned char>(announceSlot);
        strcpy(echo.senderName, announce8->senderName);
        strcpy(echo.messageText, announce8->messageText);
        g_pNetMgr->Send(&echo, true);
        return true;
      } else {
        TurnEventCKickMessagePacket kick;
        kick.messageTag = kControlTagTime; // 'time'
        short activeNation8 = g_pSimMgr->GetPlayerCountry();
        kick.eventCode = 0;
        kick.activeNationId = static_cast<unsigned char>(activeNation8);
        kick.fromNetworkId = 0;
        kick.eventCode = 0xc;
        kick.toNetworkId = 0;
        kick.targetNationBitmask = 0xff;
        kick.messageLength = 0;
        kick.messageLength = 0x11c;
        g_pSimMgr->GetPlayerCountry();
        kick.toNetworkId = announce8->fromNetworkId;
        kick.kickerNationId = -1;
        CString kickText;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&kickText, 0x2759, 2);
        strcpy(kick.messageText, kickText);
        g_pNetMgr->Send(&kick, false);
        return true;
      }
    }
    for (int scanSlot = 0; scanSlot < 7; ++scanSlot) {
      if (nationSessionIds[scanSlot] == announce8->fromNetworkId) {
        nationSessionIds[scanSlot] = 0;
        nationStatusTags[scanSlot] = kSessionTagUnas; // 'suna'
        const char* emptyName = g_szEmptyString;
        LobbyChatEvent9Packet vacate;
        vacate.InitializeEmitEventHeaderWithActiveNation();
        vacate.eventCode = 0;
        vacate.fromNetworkId = 0;
        vacate.nationSlot = static_cast<unsigned char>(scanSlot);
        vacate.toNetworkId = 0;
        vacate.toNetworkId = 0;
        vacate.messageLength = 0;
        vacate.sessionId = 0;
        vacate.messageLength = 0x64;
        vacate.eventCode = 9;
        strcpy(vacate.senderName, emptyName);
        strcpy(vacate.messageText, emptyName);
        g_pNetMgr->Send(&vacate, true);
      }
    }
    if (announceSlot != -1) {
      LobbyChatEvent9Packet claim;
      claim.InitializeEmitEventHeaderWithActiveNation();
      claim.eventCode = 0;
      claim.sessionId = announce8->fromNetworkId;
      claim.fromNetworkId = 0;
      claim.eventCode = 9;
      claim.toNetworkId = 0;
      claim.messageLength = 0;
      claim.toNetworkId = 0;
      claim.messageLength = 0x64;
      claim.nationSlot = static_cast<unsigned char>(announceSlot);
      strcpy(claim.senderName, announce8->senderName);
      strcpy(claim.messageText, announce8->messageText);
      g_pNetMgr->Send(&claim, true);
      return true;
    }
    break;
  }
  case 9: {
    LobbyChatEvent9Packet* chat = static_cast<LobbyChatEvent9Packet*>(packet);
    if (chat->nationSlot != 0xf3) {
      int slot9 = static_cast<char>(chat->nationSlot);
      int sessionId = chat->sessionId;
      {
        CString senderName(chat->senderName);
        defaultNationTextSlots[slot9] = senderName;
      }
      {
        CString messageText9(chat->messageText);
        nationDisplayNameSlots[slot9] = messageText9;
      }
      int oldSessionId = nationSessionIds[slot9];
      nationSessionIds[slot9] = sessionId;
      bool isLocal;
      if (sessionId == g_pNetMgr->GetPlayerID() && sessionId != 0) {
        isLocal = true;
        activeNationTagIndex = static_cast<unsigned char>(slot9);
      } else {
        isLocal = false;
      }
      CString statusText;
      if (sessionId == 0) {
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&statusText, 0x2759, 1);
        nationStatusTags[slot9] = kSessionTagUnas; // 'suna'
      } else {
        statusText = nationDisplayNameSlots[slot9];
        unsigned char sessionBusy;
        if (sessionPhaseTag == kSessionTagGoin && g_pSimMgr->GetPlayerCountry() != -1) {
          sessionBusy = 1;
        } else {
          sessionBusy = 0;
        }
        nationStatusTags[slot9] = sessionBusy ? kSessionTagBusy : kSessionTagRedy;
      }
      nationDisplayNameSlots[slot9] = statusText;
      defaultNationTextSlots[slot9] = nationDisplayNameSlots[slot9];
      TLoungeDialog* lounge;
      if (lobbyDialogView != 0 && lobbyDialogView->IsKindOf(RUNTIME_CLASS(TLoungeDialog)) != 0) {
        lounge = (TLoungeDialog*)lobbyDialogView;
      } else {
        lounge = 0;
      }
      if (lounge != 0) {
        TStaticText* nameLabel = (TStaticText*)lounge->FindSubView(kControlTagNam0 + slot9);
        nameLabel->AssertValid();
        CString normalizedName = g_pLanguageMgr->StripCodeStr(statusText);
        nameLabel->SetTextAndMaybeRefresh(&normalizedName, true);
        ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameLabel, 0, 0xe,
                                      isLocal ? 0x2b6c : 0x2b6b, isLocal ? 0x2b6b : 0x2b6c);
        if (oldSessionId == g_pNetMgr->GetPlayerID() || sessionId == g_pNetMgr->GetPlayerID()) {
          int mySlot = 6;
          while (mySlot >= 0 && nationSessionIds[mySlot] != g_pNetMgr->GetPlayerID()) {
            --mySlot;
          }
          TMapPreviewView* mapControl =
              static_cast<TMapPreviewView*>(lounge->FindSubView(kControlTagMapP));
          mapControl->AssertValid();
          mapControl->selectedNation = mySlot;
          mapControl->EnhancePhoto();
          CRect mapRect;
          mapControl->GetExtent(&mapRect);
          {
            ScopedMapQuickDrawContext quickDraw(mapControl);
            mapControl->Draw(&mapRect);
          }
          TPicture* coatControl = (TPicture*)lounge->FindSubView(kControlTagCoat);
          coatControl->AssertValid();
          if (mySlot >= 0) {
            coatControl->SetPictureRsrcID(static_cast<short>(mySlot + 0x120a), 1);
          }
          coatControl->Show(mySlot >= 0, 1);
        }
        if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
          bool localPresent = false;
          int liveCount = 0;
          for (int liveSlot = 0; liveSlot < 7; ++liveSlot) {
            if (nationSessionIds[liveSlot] != 0) {
              ++liveCount;
              if (nationSessionIds[liveSlot] == g_pNetMgr->GetPlayerID()) {
                localPresent = true;
              }
            }
          }
          bool canStart;
          if (liveCount < 2 || !localPresent) {
            canStart = false;
          } else {
            canStart = true;
          }
          TTextPictureButton* okayButton =
              (TTextPictureButton*)lounge->FindSubView(kControlTagOkay);
          okayButton->AssertValid();
          CString startText;
          g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&startText, 0x2759, 3);
          if (canStart) {
            okayButton->buttonText = startText;
            okayButton->RefreshControl();
          }
          okayButton->ViewEnable(canStart, 0);
          okayButton->Show(canStart, 1);
          okayButton->themeCode9A = 0x2b6c;
          okayButton->themeCode9C = 0x2b6b;
          okayButton->pointSize = 0xc;
          TView* messControl = lounge->FindSubView(kSessionTagMess);
          messControl->AssertValid();
          messControl->Show(!canStart, 1);
          LoadUiStringAndDispatchSharedMessageCommand(0x2742, canStart ? 0xa : 0xc, messControl);
          lounge->AssertValid();
          lounge->SetPictureRsrcID(canStart ? 0x11f9 : 0x11f8, 1);
        }
      }
      return true;
    }
    if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
      int sessionId2 = g_pNetMgr->GetPlayerID();
      short mySlot2 = static_cast<char>(activeNationTagIndex);
      LobbyChatEvent9Packet claim2;
      claim2.InitializeEmitEventHeaderWithActiveNation();
      claim2.nationSlot = static_cast<unsigned char>(mySlot2);
      claim2.sessionId = sessionId2;
      claim2.eventCode = 0;
      claim2.eventCode = 9;
      claim2.fromNetworkId = 0;
      claim2.toNetworkId = 0;
      claim2.messageLength = 0;
      claim2.toNetworkId = 0;
      claim2.messageLength = 0x64;
      strcpy(claim2.senderName, playerNameString);
      strcpy(claim2.messageText, playerNameMirror);
      g_pNetMgr->Send(&claim2, true);
      return true;
    }
    break;
  }
  case 0xc: {
    TurnEventCKickMessagePacket* kickView = static_cast<TurnEventCKickMessagePacket*>(packet);
    int localSlot = g_pSimMgr->GetPlayerCountry();
    if (localSlot == -1) {
      int sessionIdC = g_pNetMgr->GetPlayerID();
      int probe;
      for (probe = 0; probe < 7; ++probe) {
        if (g_pGameFlowState->nationSessionIds[probe] == sessionIdC) {
          break;
        }
      }
      localSlot = probe < 7 ? probe : -1;
    }
    if (localSlot != -1 && (kickView->targetNationBitmask & (1 << localSlot)) == 0) {
      return true;
    }
    int kickerNation = kickView->kickerNationId;
    CString messageTextC(kickView->messageText);
    CString templateTextC;
    CString titleText;
    if (kickerNation != -1 && kickerNation != localSlot) {
      g_pSimMgr->GetString(0x2749, 7, &templateTextC);
      scanBracketExpressions(g_pSimMgr, &titleText, static_cast<const char*>(templateTextC),
                             static_cast<const char*>(defaultNationTextSlots[kickerNation]));
    } else {
      BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &titleText, 0x2749, 3, 0x2749, 0);
    }
    TextStyle styleDescriptor;
    styleDescriptor.textColor = 0;
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xc, 0x2b67);
    TWindow* dialog = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMinisterMessage));
    if (dialog == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr, 0x7ef);
    }
    dialog->SetModality(true);
    TDialogBehavior* content = dialog->GetDialogBehavior();
    if (content != 0) {
      content->defaultCommandCode = kControlTagOkay; // 'okay'
    }
    CPoint placement;
    g_pViewMgr->GetTopLeftFor(dialog, &placement);
    dialog->Locate(placement, false);
    TPicture* goldPicture = static_cast<TPicture*>(dialog->FindSubView(kControlTagDialog));
    goldPicture->AssertValid();
    if (goldPicture == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr, 0x7fd);
    }
    goldPicture->SetPictureRsrcID(0x24cd, 0);
    TPicture* coatPicture = static_cast<TPicture*>(dialog->FindSubView(kControlTagCoat));
    coatPicture->AssertValid();
    if (coatPicture == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr, 0x802);
    }
    coatPicture->SetPictureRsrcID(static_cast<short>(kickerNation + 0x251c), 0);
    TStaticText* titleControl = static_cast<TStaticText*>(dialog->FindSubView(kControlTagTitl));
    titleControl->AssertValid();
    if (titleControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr, 0x807);
    }
    titleControl->InstallTextStyle(styleDescriptor, 0);
    titleControl->SetJustification(1, false);
    titleControl->SetTextAndMaybeRefresh(&titleText, false);
    TDeluxeText* infoControl = static_cast<TDeluxeText*>(dialog->FindSubView(kControlTagInfo));
    infoControl->AssertValid();
    infoControl->StuffBuffer(static_cast<const char*>(messageTextC), messageTextC.GetLength());
    infoControl->SetTextStyle(styleDescriptor, false);
    unsigned char savedProcessPrimary = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
    if (kickerNation != -1 || localSlot != -1) {
      TPicture* cancelButton = static_cast<TPicture*>(dialog->FindSubView(kControlTagCncl));
      cancelButton->AssertValid();
      cancelButton->controlTag = kSessionTagRsvp; // 'rsvp'
      cancelButton->Show(1, 0);
      cancelButton->ViewEnable(1, 0);
      cancelButton->SetPictureRsrcID(0x53a, 0);
    }
    int responseTag = dialog->PoseModally();
    dialog->Close();
    dialog->Free();
    if (responseTag == kSessionTagRsvp) { // 'rsvp'
      TPoseMessageDialog* poseCommand = new TPoseMessageDialog();
      poseCommand->kickedByNationSlot = kickerNation;
      poseCommand->ICommand(kSessionTagPose, g_pAmbitApplication, 0, 0, 0);
      g_pAmbitApplication->DispatchUiSelectionToHandler(poseCommand);
    }
    g_pGameFlowState->processPrimaryEventQueue = savedProcessPrimary;
    break;
  }
  case 1: {
    // Adopt the host's remaining pending-nation bitmask.
    pendingNationBitmask = static_cast<TurnEvent1PendingMaskPacket*>(packet)->pendingMask;
    break;
  }
  case 2: {
    // Apply the relation-matrix sync payload unless the baseline-refresh flag is set.
    TurnEvent2SyncPacket* syncPacket = static_cast<TurnEvent2SyncPacket*>(packet);
    if (syncPacket->flag20) {
      return true;
    }
    g_pDiplomacyTurnStateManager->HandleDiplomaticStandingsMsg(syncPacket);
    break;
  }
  case 0xd:
    // Re-emit the event-0xE/9 session context packets for the requesting session.
    EmitTurnEventEAnd9SessionContextPackets(packet);
    break;
  case 0xe: {
    TurnEventESessionInitPacket* sessionInit = static_cast<TurnEventESessionInitPacket*>(packet);
    g_pSimMgr->SetDifficultyLevel(static_cast<eDifficulty>(sessionInit->difficultyLevel));
    g_pSimMgr->useLocalizedNameTables = sessionInit->nameTableFlag;
    {
      CString hostGameName(sessionInit->hostGameName);
      gameNameString = hostGameName;
    }
    scenarioSelectionTag = sessionInit->scenarioTag;
    queueSyncDword = sessionInit->saveSlotDword5C;
    sessionPhaseTag = kSessionTagInit; // 'init'
    if (scenarioSelectionTag == kControlTagLoad) {
      bool probed = BuildSaveSlotPathAndProbeMetadata(queueSyncDword, g_pszClientSavePrefix);
      if (probed == 0) {
        CString messageTextE;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageTextE, 0x2742, 0x14);
        g_pViewMgr->ModalMessage(messageTextE, g_ptNationAwolModalMessage, 0, 0);
        TCancelGameOptionsCommand* cancelCommand = new TCancelGameOptionsCommand();
        cancelCommand->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0, 0);
        g_pAmbitApplication->DispatchUiSelectionToHandler(cancelCommand);
        return true;
      }
      g_pGameFlowState->lobbyDialogView = 0;
      g_pGameFlowState->sessionPhaseTag = kSessionTagGoin; // 'goin'
      g_pGameFlowState->RecalcPlayerName(-1);
      return true;
    } else if (scenarioSelectionTag == kControlTagRand) {
      g_pSimMgr->CreateSimObjects(true);
      g_pSimMgr->CreatePlanet(1, sessionInit->mapSeedText, sessionInit->mapParamByte39);
    } else if (scenarioSelectionTag >= kControlTagScn0 && scenarioSelectionTag <= kSessionTagScz9) {
      g_pSimMgr->CreateSimObjects(true);
      unsigned char rebuilt = g_pSimMgr->LoadScenario(scenarioSelectionTag - kControlTagScn0);
      if (rebuilt == 0) {
        CString messageTextE2;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageTextE2, 0x2742, 2);
        g_pViewMgr->ModalMessage(messageTextE2, g_ptNationAwolModalMessage, 0, 0);
        TCancelGameOptionsCommand* cancelCommand2 = new TCancelGameOptionsCommand();
        cancelCommand2->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0, 0);
        g_pAmbitApplication->DispatchUiSelectionToHandler(cancelCommand2);
        return true;
      }
    } else {
      return true;
    }
    TLoungeDialog* loungeE;
    if (lobbyDialogView != 0 && lobbyDialogView->IsKindOf(RUNTIME_CLASS(TLoungeDialog)) != 0) {
      loungeE = (TLoungeDialog*)lobbyDialogView;
    } else {
      loungeE = 0;
    }
    loungeE->YouHaveNewGameData();
    break;
  }
  case 3: {
    sessionPhaseTag = kSessionTagGoin; // 'goin'
    resumePhase = kGamePhaseNone;
    syncPhase = kGamePhaseNone;
    int sessionId3 = g_pNetMgr->GetPlayerID();
    int matchSlot = 0;
    int* sessionIdCursor = nationSessionIds;
    do {
      if (*sessionIdCursor == sessionId3) {
        break;
      }
      ++matchSlot;
      ++sessionIdCursor;
    } while (matchSlot < 7);
    if (matchSlot >= 7) {
      matchSlot = -1;
    }
    if (matchSlot == -1) {
      TCancelGameOptionsCommand* cancelCommand3 = new TCancelGameOptionsCommand();
      cancelCommand3->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0, 0);
      g_pAmbitApplication->DispatchUiSelectionToHandler(cancelCommand3);
      return true;
    }
    int tagSlot = g_pSimMgr->GetPlayerCountry();
    if (tagSlot == -1) {
      tagSlot = static_cast<char>(activeNationTagIndex);
    }
    nationStatusTags[tagSlot] = kSessionTagBusy; // 'busy'
    NationStatusEvent25Packet statusPacket;
    statusPacket.messageTag = kControlTagTime; // 'time'
    statusPacket.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
    statusPacket.eventCode = 0;
    statusPacket.fromNetworkId = 0;
    statusPacket.eventCode = 0x25;
    statusPacket.messageLength = 0;
    statusPacket.messageLength = 0x34;
    for (int tagInit = 0; tagInit < 7; ++tagInit) {
      statusPacket.statusTags[tagInit] = kSessionTagUnkn; // 'unkn'
    }
    statusPacket.toNetworkId = 0;
    statusPacket.statusTags[tagSlot] = kSessionTagBusy; // 'busy'
    g_pNetMgr->Send(&statusPacket, false);
    g_pSimMgr->StartNextPhase();
    break;
  }
  case 0x10:
    g_pSimMgr->StartNextPhase();
    break;
  case 0x11: {
    // Masked byte/word/dword poke into a global map table; the host rebroadcasts.
    TurnEvent11MapPokePacket* poke = static_cast<TurnEvent11MapPokePacket*>(packet);
    switch (poke->pokeWidthCode) {
    case 1: {
      unsigned char* bufferBase1 = 0;
      if (poke->bufferSelector == 0) {
        bufferBase1 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);
      } else if (poke->bufferSelector == 1) {
        bufferBase1 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->cityScoreTable);
      }
      unsigned char maskByte = static_cast<unsigned char>(poke->pokeMask);
      unsigned char* target1 = bufferBase1 + poke->byteOffset;
      *target1 =
          static_cast<unsigned char>((*target1 & static_cast<unsigned char>(~maskByte)) |
                                     (static_cast<unsigned char>(poke->pokeValue) & maskByte));
      break;
    }
    case 2: {
      unsigned char* bufferBase2 = 0;
      if (poke->bufferSelector == 0) {
        bufferBase2 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);
      } else if (poke->bufferSelector == 1) {
        bufferBase2 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->cityScoreTable);
      }
      short* target2 = reinterpret_cast<short*>(bufferBase2 + poke->byteOffset);
      *target2 =
          static_cast<short>((*target2 & ~poke->pokeMask) | (poke->pokeValue & poke->pokeMask));
      break;
    }
    case 4: {
      unsigned char* bufferBase4 = 0;
      if (poke->bufferSelector == 0) {
        bufferBase4 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->terrainStateTable);
      } else if (poke->bufferSelector == 1) {
        bufferBase4 = reinterpret_cast<unsigned char*>(g_pGlobalMapState->cityScoreTable);
      }
      int maskBits = poke->pokeMask;
      int* target4 = reinterpret_cast<int*>(bufferBase4 + poke->byteOffset);
      *target4 = (poke->pokeValue & maskBits) | (*target4 & ~maskBits);
      break;
    }
    default:
      break;
    }
    bool hosting11 = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (!hosting11) {
      return true;
    }
    TurnEvent11MapPokePacket rebroadcast = *poke;
    rebroadcast.eventCode = 0;
    rebroadcast.fromNetworkId = 0;
    rebroadcast.toNetworkId = 0;
    rebroadcast.eventCode = 0x11;
    rebroadcast.messageLength = 0;
    rebroadcast.messageLength = 0x28;
    rebroadcast.toNetworkId = 0;
    g_pNetMgr->Send(&rebroadcast, false);
    break;
  }
  case 0x12: {
    // City ownership change via the map manager virtual.
    TurnEvent12Packet* cityOwner = static_cast<TurnEvent12Packet*>(packet);
    g_pGlobalMapState->ChangeProvinceOwner(cityOwner->shortA, cityOwner->shortB);
    break;
  }
  case 0x13: {
    // Queue the nine-dword payload into the nation's event bucket.
    TurnEvent13NewsPacket* nationPayload = static_cast<TurnEvent13NewsPacket*>(packet);
    g_pNewsMgr->AddEvent(nationPayload->nationSlot, &nationPayload->newsEvent, true);
    break;
  }
  case 0x20: {
    TurnEvent20TreatyNewsPacket* treatyNews = static_cast<TurnEvent20TreatyNewsPacket*>(packet);
    g_pNewsMgr->AddTreatyEvent(static_cast<InterNationEventKind>(treatyNews->eventKind),
                               treatyNews->nationA, treatyNews->nationB, true);
    break;
  }
  case 0x21: {
    TurnEvent21ShortageNewsPacket* shortageNews =
        static_cast<TurnEvent21ShortageNewsPacket*>(packet);
    g_pNewsMgr->AddShortageEvent(shortageNews->subjectNation, shortageNews->affectedNation,
                                 shortageNews->relatedNation, true);
    break;
  }
  case 0x22: {
    TurnEvent22MiscNewsPacket* miscNews = static_cast<TurnEvent22MiscNewsPacket*>(packet);
    g_pNewsMgr->AddMiscEvent(miscNews->nationSlotOrAll, miscNews->storyCode, true);
    break;
  }
  case 0x1d: {
    // War-transition check ('i') or propagate on the active nation.
    TurnEvent1DWarTransitionPacket* warTransition =
        static_cast<TurnEvent1DWarTransitionPacket*>(packet);
    TGreatPower* nation1D = g_apNationStates[g_pSimMgr->GetPlayerCountry()];
    if (warTransition->actionCode == 'i') {
      nation1D->ConsiderWarOfIntervention(warTransition->nationA1D, warTransition->nationB1E);
    } else {
      nation1D->ConsiderWarOfAlliance(warTransition->nationA1D, warTransition->nationB1E,
                                      warTransition->mode1F);
    }
    break;
  }
  case 0x1e: {
    TurnEvent1EDiplomacyActionPacket* action =
        static_cast<TurnEvent1EDiplomacyActionPacket*>(packet);
    if (action->actionCode == 'a') {
      if (action->flag21 != 0) {
        TGreatPower* nation1E = g_apNationStates[action->nation];
        if (action->flag20 == 0) {
          nation1E->DeclareWarOn(action->nationB1E, 2, action->nationA1D);
        } else {
          nation1E->DeclareWarOn(action->nationA1D, 2, action->nationB1E);
        }
      } else {
        char targetNation;
        bool relationMode;
        if (action->flag20 == 0) {
          targetNation = action->nationA1D;
          relationMode = true;
        } else {
          targetNation = action->nationB1E;
          relationMode = false;
        }
        g_pDiplomacyTurnStateManager->TerminateAlliance(action->nation, targetNation, relationMode);
      }
    } else if (action->actionCode == 'i' && action->flag21 != 0) {
      if (!g_pDiplomacyTurnStateManager->AreAtWar(action->nation, action->nationB1E)) {
        g_apNationStates[action->nation]->DeclareWarOn(action->nationB1E, 1, action->nationA1D);
      } else {
        TMinor* minor1E = g_apSecondaryNationStateSlots[action->nationA1D];
        if (minor1E->DecodeOwnerNationSlot() != static_cast<short>(action->nation)) {
          minor1E->ChangeMaster(action->nation, 1);
        }
      }
    }
    TNextDiplomationCommand* nextCommand = new TNextDiplomationCommand();
    nextCommand->PostThyself();
    break;
  }
  case 0x1a: {
    TurnEvent1ANationActionPacket* nationAction =
        static_cast<TurnEvent1ANationActionPacket*>(packet);
    bool isClientSession = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
    if (isClientSession) {
      for (int counterSlot = 0; counterSlot < 7; ++counterSlot) {
        TGreatPower* counterNation = g_apNationStates[counterSlot];
        if (counterNation != 0) {
          counterNation->availableMerchantCapacity = nationAction->counterA2BySlot[counterSlot];
        }
      }
    }
    short sourceNation = nationAction->respondingNation;
    if (sourceNation != g_pSimMgr->GetPlayerCountry()) {
      g_pViewMgr->ShowOfferSheet(sourceNation, nationAction->offeringNation, 0, 0, 0);
      return true;
    }
    bool stillClientSession = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
    if (!stillClientSession) {
      return true;
    }
    g_pViewMgr->ShowOfferSheet(sourceNation, nationAction->offeringNation,
                               nationAction->proposedAmount, nationAction->maxAmount, 0);
    break;
  }
  case 0x1b: {
    // Append one tracked-slot entry to the nation.
    TurnEvent1BDealBookEntryPacket* trackedEntry =
        static_cast<TurnEvent1BDealBookEntryPacket*>(packet);
    g_apNationStates[trackedEntry->nationSlot]->AddToDealBook(
        trackedEntry->trackedKind, trackedEntry->targetNation, trackedEntry->trackedValue,
        trackedEntry->trackedSlotIndex, trackedEntry->trackedPayload);
    break;
  }
  case 0x1c: {
    TurnEvent1CDealResultPacket* dealResult = static_cast<TurnEvent1CDealResultPacket*>(packet);
    g_pTradeMgr->SetDealResults(dealResult->sourceNation, dealResult->targetNation,
                                dealResult->amount, dealResult->maximumAmount,
                                dealResult->commodityType,
                                static_cast<unsigned char>(dealResult->shortfallFlag), true);
    bool hosting1C = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (!hosting1C) {
      return true;
    }
    TNextTradeCommand* tradeCommand = new TNextTradeCommand();
    tradeCommand->INextTradeCommand();
    g_pAmbitApplication->DispatchUiSelectionToHandler(tradeCommand);
    break;
  }
  case 0x14: {
    // Add the amount to the terrain-slot nation's field-0x10 metric.
    TurnEvent14NationMetricPacket* metricDelta =
        static_cast<TurnEvent14NationMetricPacket*>(packet);
    g_apTerrainTypeDescriptorTable[metricDelta->nationSlot]->AddToTreasury(metricDelta->amount);
    break;
  }
  case 0x15: {
    TurnEvent15Packet* needState = static_cast<TurnEvent15Packet*>(packet);
    TGreatPower* nation15 = g_apNationStates[needState->nationSlot];
    nation15->treasuryValue = needState->treasuryValue;
    nation15->grantTotalCost = needState->grantTotalCost;
    for (int needType = 0; needType < kResourceKindCount; ++needType) {
      nation15->needCurrentByType[needType] = needState->needCurrentByType[needType];
      nation15->needTargetByType[needType] = needState->needTargetByType[needType];
      nation15->relationDeltaCurrent[needType] = needState->relationDeltaCurrent[needType];
      nation15->purchasedItemsByResource[needType] = needState->purchasedItemsByResource[needType];
      nation15->itemPotentials[needType] = needState->itemPotentials[needType];
      for (int aidRow = 0; aidRow < 0x10; ++aidRow) {
        nation15->aidAllocationMatrix[aidRow * 0x17 + needType] =
            needState->aidAllocationMatrix[aidRow * 0x17 + needType];
      }
    }
    nation15->budgetPoolBase = needState->budgetPoolBase;
    nation15->budgetPoolDelta = needState->budgetPoolDelta;
    nation15->diplomacyBudgetBase = needState->diplomacyBudgetBase;
    nation15->escalationCounter = needState->escalationCounter;
    nation15->pendingCommitmentCost = needState->pendingCommitmentCost;
    nation15->pressureCounter = needState->pressureCounter;
    break;
  }
  case 0x19: {
    // Receive side of SendNationStateMessage.
    TurnEvent19Packet* stateArrays = static_cast<TurnEvent19Packet*>(packet);
    short nationSlot19 = stateArrays->nationSlot;
    if (nationSlot19 == g_pSimMgr->GetPlayerCountry()) {
      return true;
    }
    TGreatPower* nation19 = g_apNationStates[nationSlot19];
    nation19->transportCapacity = stateArrays->transportCapacity;
    for (int industryActionSlot19 = 0; industryActionSlot19 < kIndustryActionSlotCount;
         ++industryActionSlot19) {
      nation19->city->orderCountByType[industryActionSlot19] =
          stateArrays->orderCountByType[industryActionSlot19];
    }
    nation19->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    for (int stockSlot19 = 0; stockSlot19 < 0x17; ++stockSlot19) {
      nation19->SetStockpile(static_cast<short>(stockSlot19),
                             stateArrays->externalStateByTarget[stockSlot19]);
    }
    nation19->InitializeTradeStatus();
    for (int metricSlot19 = 0; metricSlot19 < 0x11; ++metricSlot19) {
      nation19->SetItemPotentials(static_cast<short>(metricSlot19),
                                  stateArrays->metricBySlot7C[metricSlot19]);
    }
    nation19->RememberTradeBids();
    for (int target19 = 0; target19 < 0x17; ++target19) {
      nation19->diplomacyPolicyByNation[target19] = stateArrays->diplomacyPolicyByNation[target19];
      nation19->diplomacyGrantByNation[target19] = stateArrays->diplomacyGrantByNation[target19];
      nation19->tradePolicyByNation[target19] = stateArrays->tradePolicyByNation[target19];
    }
    break;
  }
  case 0x2c: {
    // Receive side of SendCityStateMessage.
    TurnEvent2CPacket* composite = static_cast<TurnEvent2CPacket*>(packet);
    int nationSlot2C = composite->nationSlot;
    if (nationSlot2C == g_pSimMgr->GetPlayerCountry()) {
      return true;
    }
    g_apNationStates[nationSlot2C]->specialResourceTradeBalance =
        composite->specialResourceTradeBalance;
    g_apNationStates[nationSlot2C]->aidAllocationTotal = composite->aidAllocationTotal;
    TCity* city2C;
    if (g_apNationStates[nationSlot2C] == 0) {
      city2C = 0;
    } else {
      city2C = g_apNationStates[nationSlot2C]->city;
    }
    for (int militaryKind = 0; militaryKind < kMilitaryUnitKindCount; ++militaryKind) {
      city2C->militaryRecruitCountByKind[militaryKind] =
          composite->militaryRecruitCountByKind[militaryKind];
    }
    for (int civilianKind = 0; civilianKind < kCivilianUnitKindCount; ++civilianKind) {
      city2C->civilianRecruitCountByKind[civilianKind] =
          composite->civilianRecruitCountByKind[civilianKind];
    }
    for (int industryActionSlot2C = 0; industryActionSlot2C < kIndustryActionSlotCount;
         ++industryActionSlot2C) {
      city2C->orderCountByType[industryActionSlot2C] =
          composite->orderCountByType[industryActionSlot2C];
    }
    g_apNationStates[nationSlot2C]->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    city2C->rollingItemProductionScore = composite->cityRollingItemProductionScore;
    city2C->powerAvailable = composite->cityFieldB4;
    short* stock2C = city2C->stockByType;
    for (int stockType = 0; stockType < kResourceKindCount; ++stockType) {
      stock2C[stockType] = composite->cityStock[stockType];
    }
    for (int orderSlot2C = 0; orderSlot2C < 0x10; ++orderSlot2C) {
      city2C->productionOrderTable[orderSlot2C] = composite->productionOrderTable[orderSlot2C];
    }
    for (int accumSlot = 0; accumSlot < 0x10; ++accumSlot) {
      city2C->productionAccum[accumSlot] = composite->productionAccum[accumSlot];
    }
    city2C->populationGrowthPenaltyTicks = composite->populationGrowthPenaltyTicks;
    // Second, duplicate copy of the city stock block - original behavior, kept as-is.
    for (int stockType2 = 0; stockType2 < kResourceKindCount; ++stockType2) {
      stock2C[stockType2] = composite->cityStock[stockType2];
    }
    for (int record2C = 0; record2C < 0x17; ++record2C) {
      TProductionOrder* order2C = city2C->orderSlots[record2C];
      if (order2C != 0) {
        order2C->accumulatedValue = composite->orderAccumulatedValues[record2C];
      }
    }
    TPopulationMgr* summary2C = city2C->productionSummary;
    summary2C->populationCount = composite->popFieldAt8;
    summary2C->populationCountFloat = composite->popFieldAtC;
    summary2C->strength = composite->popStockLevel;
    summary2C->extraAt1e = composite->popExtraAt1e;
    summary2C->fieldAt20 = composite->popFieldAt20;
    summary2C->baselineSlots->lowSkillCount = composite->popBucketWords[0];
    summary2C->baselineSlots->mediumSkillCount = composite->popBucketWords[1];
    summary2C->baselineSlots->highSkillCount = composite->popBucketWords[2];
    summary2C->productionSlots->lowSkillCount = composite->popBucketWords[3];
    summary2C->productionSlots->mediumSkillCount = composite->popBucketWords[4];
    summary2C->productionSlots->highSkillCount = composite->popBucketWords[5];
    summary2C->pendingDeltaSlots->lowSkillCount = composite->popBucketWords[6];
    summary2C->pendingDeltaSlots->mediumSkillCount = composite->popBucketWords[7];
    summary2C->pendingDeltaSlots->highSkillCount = composite->popBucketWords[8];
    break;
  }
  case 0x2d: {
    // Minor-nation need snapshot.
    TurnEvent2DMinorNeedPacket* minorNeed = static_cast<TurnEvent2DMinorNeedPacket*>(packet);
    TMinor* minor2D = g_apSecondaryNationStateSlots[minorNeed->nationSlot];
    for (int needSlot2D = 0; needSlot2D < kNationSlotCount; ++needSlot2D) {
      minor2D->tradePolicyByNation[needSlot2D] = minorNeed->tradePolicyByNation[needSlot2D];
    }
    break;
  }
  case 0x16: {
    // Queue a diplomacy proposal code on the addressed nation.
    TurnEvent16DiplomacyProposalPacket* proposal =
        static_cast<TurnEvent16DiplomacyProposalPacket*>(packet);
    g_apNationStates[proposal->nationSlot]->AddOfferFrom(proposal->sourceNationSlot,
                                                         proposal->proposalCode);
    break;
  }
  case 0x17: {
    // Resolve a pending diplomacy proposal.
    TurnEvent17ProposalResolutionPacket* resolution =
        static_cast<TurnEvent17ProposalResolutionPacket*>(packet);
    if (resolution->acceptedFlag) {
      g_apNationStates[resolution->nationSlot]->AcceptOffer(resolution->proposalIndex);
    } else {
      g_apNationStates[resolution->nationSlot]->RejectOffer(resolution->proposalIndex);
    }
    break;
  }
  case 0x18: {
    // Host broadcast of all seven great powers' diplomacy arrays.
    TurnEvent18DiplomacyArraysPacket* arrays =
        static_cast<TurnEvent18DiplomacyArraysPacket*>(packet);
    for (int arraySlot = 0; arraySlot < 7; ++arraySlot) {
      TGreatPower* arrayNation = g_apNationStates[arraySlot];
      if (arrayNation != 0) {
        for (int arrayTarget = 0; arrayTarget < 0x17; ++arrayTarget) {
          arrayNation->diplomacyPolicyByNation[arrayTarget] =
              arrays->diplomacyPolicyByNation[arraySlot][arrayTarget];
          arrayNation->diplomacyGrantByNation[arrayTarget] =
              arrays->diplomacyGrantByNation[arraySlot][arrayTarget];
          arrayNation->tradePolicyByNation[arrayTarget] =
              arrays->tradePolicyByNation[arraySlot][arrayTarget];
        }
      }
    }
    break;
  }
  case 0x28:
  case 0x2e:
  case 0x2f:
  case 0x30:
  case 0x31:
  case 0x32: {
    g_nSaveFormatVersion = kSessionTagNetX; // 'netX'
    int packetBytes = packet->messageLength;
    HGLOBAL packetMemory = GlobalAlloc(GMEM_MOVEABLE, packetBytes);
    void* streamBuffer = GlobalLock(packetMemory);
    memmove(streamBuffer, packet, packetBytes);
    GlobalUnlock(packetMemory);
    THandleStream* reader = new THandleStream();
    reader->IHandleStream(packetMemory, 0x10);
    ReadMessageFrom(reader);
    reader->Free();
    g_nSaveFormatVersion = -1;
    break;
  }
  case 0x1f: {
    // Session/game-flow four-cc status dispatcher.
    TurnEvent1FStatusPacket* gameState = static_cast<TurnEvent1FStatusPacket*>(packet);
    switch (gameState->statusTag) {
    case kControlTagAbdi: { // 'abdi' - nation abdicated: notice; host replaces the slot with an AI
      CString templateTextAbdi;
      CString formattedAbdi;
      CString nationNameAbdi;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&templateTextAbdi, 0x2737, 0x32);
      g_apTerrainTypeDescriptorTable[gameState->controlValue]->FormatOverlayTerrainLabelText(
          &nationNameAbdi);
      scanBracketExpressions(g_pSimMgr, &formattedAbdi, static_cast<const char*>(templateTextAbdi),
                             static_cast<const char*>(nationNameAbdi));
      g_pViewMgr->PostModalMessage(&formattedAbdi, 0);
      bool hostingAbdi = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
      if (hostingAbdi) {
        DehumanizePlayer(gameState->controlValue);
      }
      return true;
    }
    case kSessionTagAced: { // 'aced' - accession notice; the affected local player posts 'gwen'
      bool isLocalNationAced = g_pSimMgr->GetPlayerCountry() == gameState->controlValue;
      CString templateTextAced;
      CString formattedAced;
      CString nationNameAced;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&templateTextAced, 0x2742,
                                                          isLocalNationAced ? 0x23 : 0x1c);
      g_apTerrainTypeDescriptorTable[gameState->controlValue]->FormatOverlayTerrainLabelText(
          &nationNameAced);
      scanBracketExpressions(g_pSimMgr, &formattedAced, static_cast<const char*>(templateTextAced),
                             static_cast<const char*>(nationNameAced));
      g_pViewMgr->PostModalMessage(&formattedAced, 0);
      if (isLocalNationAced) {
        g_pAmbitApplication->CreateAndQueueTurnEventPacketTagGWEN();
      }
      return true;
    }
    case kSessionTagUhed: // 'uhed' - nation left unheaded: replace with AI locally
      DehumanizePlayer(gameState->controlValue);
      return true;
    case kControlTagCgam: { // 'cgam' - cancel game
      TCancelGameOptionsCommand* cancelCommandCgam = new TCancelGameOptionsCommand();
      cancelCommandCgam->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0, 0);
      g_pAmbitApplication->DispatchUiSelectionToHandler(cancelCommandCgam);
      CString messageCgam;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageCgam, 0x2742, 0x27);
      g_pViewMgr->PostModalMessage(&messageCgam, 0);
      return true;
    }
    case kControlTagLose: // 'lose' - the named nation lost
      g_apNationStates[gameState->controlValue]->SorryYouLose();
      return true;
    case kSessionTagFoff: { // 'foff' - seat refused: show string[value1C], post the cancel command
      CString messageFoff;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageFoff, 0x2742,
                                                          gameState->controlValue);
      g_pViewMgr->PostModalMessage(&messageFoff, 0);
      TCancelGameOptionsCommand* cancelCommandFoff = new TCancelGameOptionsCommand();
      cancelCommandFoff->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0, 0);
      g_pAmbitApplication->DispatchUiSelectionToHandler(cancelCommandFoff);
      return true;
    }
    case kControlTagName: // 'name' - refresh the status board row (global manager receiver)
      g_pGameFlowState->RecalcPlayerName(gameState->controlValue);
      return true;
    case kControlTagLost: { // 'lost' - connection to a nation lost
      int lostCode = gameState->controlValue;
      bool droppedFlag = (lostCode & 0xff00) != 0;
      int lostNationSlot = lostCode & 0xff;
      bool isLocalNationLost = lostNationSlot == g_pSimMgr->GetPlayerCountry();
      CString templateTextLost;
      CString formattedLost;
      CString nationNameLost;
      g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(
          &templateTextLost, 0x2742, (droppedFlag ? 2 : 0) + (isLocalNationLost ? 1 : 0) + 0x1f);
      g_apTerrainTypeDescriptorTable[lostNationSlot]->FormatOverlayTerrainLabelText(
          &nationNameLost);
      scanBracketExpressions(g_pSimMgr, &formattedLost, static_cast<const char*>(templateTextLost),
                             static_cast<const char*>(nationNameLost));
      g_pViewMgr->PostModalMessage(&formattedLost, 0);
      if (isLocalNationLost) {
        bool clientSessionLost = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
        if (clientSessionLost) {
          g_pAmbitApplication->CreateAndQueueTurnEventPacketTagGWEN();
        }
      }
      return true;
    }
    case kControlTagQuit:   // 'quit'
    case kControlTagNewg: { // 'newg' - session ending: optional notice, then close or restart
      unsigned char restartFlag = gameState->controlValue;
      bool clientSessionQuit = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
      if (clientSessionQuit) {
        CString messageQuit;
        if (restartFlag != 0) {
          g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageQuit, 0x2742, 0x1d);
        } else {
          g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&messageQuit, 0x2742, 0x1e);
        }
        g_pViewMgr->PostModalMessage(&messageQuit, 0);
      }
      bool stillClientSessionQuit = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
      if (!stillClientSessionQuit && gameState->statusTag != kControlTagNewg) {
        g_pAmbitApplication->PostWmCloseToMainThreadWindow();
        return true;
      }
      g_pAmbitApplication->CreateAndQueueTurnEventPacketTagGWEN();
      return true;
    }
    case kControlTagRege: { // 'rege' - regenerate client map clip regions
      bool clientSessionRege = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
      if (clientSessionRege) {
        g_pMacViewMgr->RegenerateCountryRegions();
      }
      return true;
    }
    case kControlTagRepo: { // 'repo' - a session reports for a nation slot: seat it or refuse
      int repoSlot = gameState->controlValue & 7;
      bool hostCanSeatEmptySlot = false;
      if (g_apNationStates[repoSlot] == 0 && packet->fromNetworkId == g_pNetMgr->GetPlayerID() &&
          g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
        hostCanSeatEmptySlot = true;
      }
      if (repoSlot >= 0 && repoSlot < 7 &&
          (hostCanSeatEmptySlot ||
           (g_apNationStates[repoSlot] != 0 && (packet->fromNetworkId == g_pNetMgr->GetPlayerID() ||
                                                g_apNationStates[repoSlot]->IsRemote())))) {
        LobbyChatEvent9Packet seatAnnounce;
        seatAnnounce.messageTag = kControlTagTime; // 'time'
        seatAnnounce.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
        seatAnnounce.eventCode = 0;
        seatAnnounce.sessionId = packet->fromNetworkId;
        seatAnnounce.fromNetworkId = 0;
        seatAnnounce.eventCode = 9;
        seatAnnounce.toNetworkId = 0;
        seatAnnounce.messageLength = 0;
        seatAnnounce.toNetworkId = 0;
        seatAnnounce.messageLength = 0x64;
        seatAnnounce.nationSlot = static_cast<unsigned char>(repoSlot);
        strcpy(seatAnnounce.senderName, defaultNationTextSlots[repoSlot]);
        strcpy(seatAnnounce.messageText, nationDisplayNameSlots[repoSlot]);
        g_pNetMgr->Send(&seatAnnounce, true);
        CString formattedRepo;
        CString templateTextRepo;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&templateTextRepo, 0x2759, 0xa);
        CString nationNameRepo(defaultNationTextSlots[repoSlot]);
        scanBracketExpressions(g_pSimMgr, &formattedRepo,
                               static_cast<const char*>(templateTextRepo),
                               static_cast<const char*>(nationNameRepo));
        TurnEventCKickMessagePacket joinBroadcast;
        joinBroadcast.messageTag = kControlTagTime; // 'time'
        joinBroadcast.eventCode = 0;
        joinBroadcast.fromNetworkId = 0;
        joinBroadcast.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
        joinBroadcast.toNetworkId = 0;
        joinBroadcast.eventCode = 0xc;
        joinBroadcast.messageLength = 0;
        joinBroadcast.messageLength = 0x11c;
        joinBroadcast.targetNationBitmask = 0xff;
        joinBroadcast.kickerNationId = static_cast<signed char>(g_pSimMgr->GetPlayerCountry());
        strcpy(joinBroadcast.messageText, formattedRepo);
        joinBroadcast.eventCode = 0xc;
        joinBroadcast.kickerNationId = -1; // double-write over the active id - original
        joinBroadcast.toNetworkId = 0;
        joinBroadcast.targetNationBitmask = static_cast<unsigned char>(0xff - (1 << repoSlot));
        g_pNetMgr->Send(&joinBroadcast, true);
      } else {
        TurnEvent1FStatusPacket refuse;
        refuse.messageTag = kControlTagTime; // 'time'
        refuse.eventCode = 0;
        refuse.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
        refuse.fromNetworkId = 0;
        refuse.toNetworkId = 0;
        refuse.eventCode = 0x1f;
        refuse.messageLength = 0;
        refuse.messageLength = 0x20;
        refuse.toNetworkId = packet->fromNetworkId;
        refuse.statusTag = kSessionTagFoff; // 'foff'
        refuse.controlValue = 0x29;
        g_pNetMgr->Send(&refuse, false);
      }
      return true;
    }
    case kControlTagSave: // 'save' - latch the save flag and save with the network label
      networkSavePending = static_cast<unsigned char>(gameState->controlValue);
      SaveGameWithModeAndOptionalLabel(queueSyncDword, (char*)g_pszClientSavePrefix);
      return true;
    case kControlTagTrad: { // 'trad' - reset diplomacy level: packed (nationSlot << 16 | level)
      int tradeCode = gameState->controlValue;
      g_apNationStates[g_pSimMgr->GetPlayerCountry()]->SetTradePolicyTo(
          static_cast<short>(static_cast<unsigned int>(tradeCode) >> 0x10),
          static_cast<short>(tradeCode));
      return true;
    }
    case kSessionTagTras: // 'tras' - rebuild + discard the transport-influence map
      g_apNationStates[g_pSimMgr->GetPlayerCountry()]->TraceSupplyRoutes(0);
      return true;
    default:
      return true;
    }
  }
  case 0x23: { // patch selected fields of one map tile's terrain-state record
    TurnEvent23TileStatePacket* tileState = static_cast<TurnEvent23TileStatePacket*>(packet);
    TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[tileState->tileIndex];
    tile->ownerNationTag = tileState->record.ownerNationTag;
    tile->regionSubtypeTag = tileState->record.regionSubtypeTag;
    tile->adjacencyBits = tileState->record.adjacencyBits;
    tile->developmentClassNibbles = tileState->record.developmentClassNibbles;
    tile->pendingDevelopmentFlag = static_cast<unsigned char>(
        tile->pendingDevelopmentFlag | tileState->record.pendingDevelopmentFlag);
    tile->secondaryOwnerNationTag = tileState->record.secondaryOwnerNationTag;
    tile->activeFlags = tileState->record.activeFlags;
    break;
  }
  case 0x24: { // patch selected fields of one city-score record
    TurnEvent24CityRecordPacket* cityRecord = static_cast<TurnEvent24CityRecordPacket*>(packet);
    Province* city24 = &g_pGlobalMapState->cityScoreTable[cityRecord->cityRecordIndex];
    city24->ownerNationCode = cityRecord->record.ownerNationCode;
    city24->developmentStage = cityRecord->record.developmentStage;
    city24->fortLevel = cityRecord->record.fortLevel;
    city24->lastTurnTick = cityRecord->record.lastTurnTick;
    {
      // 10-short copy 0x82..0x95 (explicit word loop in the original, not rep movs).
      short* cityWordCursor = &city24->resourceDevelopmentCounts[0];
      short* recordWordCursor = cityRecord->record.resourceDevelopmentCounts;
      for (int wordCountdown = 0; wordCountdown < 10; ++wordCountdown) {
        *cityWordCursor = *recordWordCursor;
        ++recordWordCursor;
        ++cityWordCursor;
      }
    }
    city24->exploredByNationMask = cityRecord->record.exploredByNationMask;
    city24->resourcePresenceMask = cityRecord->record.resourcePresenceMask;
    break;
  }
  case 0x25: { // merge nation status tags; ding when exactly one nation stays busy
    NationStatusEvent25Packet* statusBoard = static_cast<NationStatusEvent25Packet*>(packet);
    int readyCount = 0;
    int busyCount = 0;
    {
      int* incomingTagCursor = statusBoard->statusTags;
      int* ownTagCursor = nationStatusTags;
      for (int tagCountdown = 0; tagCountdown < 7; ++tagCountdown) {
        if (*incomingTagCursor != kSessionTagUnkn) {
          *ownTagCursor = *incomingTagCursor;
        }
        if (*ownTagCursor == kSessionTagRedy) {
          ++readyCount;
        } else if (*ownTagCursor == kSessionTagBusy) {
          ++busyCount;
        }
        ++incomingTagCursor;
        ++ownTagCursor;
      }
    }
    if (readyCount > 0 && busyCount == 1) {
      int busySlot = g_pSimMgr->GetPlayerCountry();
      if (busySlot == -1) {
        int sessionId25 = g_pNetMgr->GetPlayerID();
        int* sessionCursor25 = g_pGameFlowState->nationSessionIds;
        for (busySlot = 0; busySlot < 7; ++busySlot) {
          if (*sessionCursor25 == sessionId25) {
            break;
          }
          ++sessionCursor25;
        }
        if (busySlot == 7) {
          busySlot = -1; // a -1 here indexes nationStatusTags[-1] below - original
                         // out-of-bounds behavior, kept as-is
        }
      }
      if (nationStatusTags[busySlot] == kSessionTagBusy && networkSavePending != 0) {
        g_pSfxPlaybackSystem->PlaySoundEffect(0x13f2, 0, 1);
      }
    }
    break;
  }
  case 0x26: { // bulk-load the diplomacy matrices into g_pDiplomacyTurnStateManager
    TurnEvent26DiplomacyMatrixPacket* matrix =
        static_cast<TurnEvent26DiplomacyMatrixPacket*>(packet);
    memcpy(g_pDiplomacyTurnStateManager->relationCodeMatrix, matrix->relationCodeMatrix,
           sizeof(g_pDiplomacyTurnStateManager->relationCodeMatrix));
    memcpy(g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix, matrix->pendingPolicyCodeMatrix,
           sizeof(g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix));
    memcpy(g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix, matrix->pendingPolicyTierMatrix,
           sizeof(g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix));
    g_pDiplomacyTurnStateManager->congressLeadership = matrix->congressLeadership;
    g_pDiplomacyTurnStateManager->congressSupport = matrix->congressSupport;
    memcpy(g_pDiplomacyTurnStateManager->comparativePowerRows, matrix->relationTailBlock,
           sizeof(matrix->relationTailBlock));
    break;
  }
  case 0x27: { // dispatch join-empire mode on one terrain-slot nation
    TurnEvent27JoinEmpirePacket* joinEmpire = static_cast<TurnEvent27JoinEmpirePacket*>(packet);
    g_apTerrainTypeDescriptorTable[joinEmpire->terrainSlot]->ChangeMaster(
        joinEmpire->targetNationSlot, joinEmpire->mode);
    break;
  }
  case 0x29: { // route a tagged tactical command to the live battle
    TacticalCommandPacket* tactical = static_cast<TacticalCommandPacket*>(packet);
    TTacticalBattle* battle = g_pActiveTacticalBattle;
    battle->AssertValid();
    TArmyTacUnit* unit = battle->SeekLinkedListCursorByNestedId(tactical->unitId);
    switch (tactical->commandTag) {
    case kControlTagDepl: // 'depl'
      battle->LaDeploy(unit, tactical->arg20, true);
      return true;
    case kControlTagDigg: // 'digg'
      battle->LaDig(unit, tactical->arg20, true);
      return true;
    case kControlTagMine: // 'mine' - the resolved unit cursor is NOT passed here
      battle->LaMine(tactical->arg20, tactical->arg24, true);
      return true;
    case kControlTagMove: // 'move'
      battle->LaMove(unit, tactical->arg20, tactical->arg24, true);
      return true;
    case kControlTagRaly: // 'raly'
      battle->LaRally(unit, tactical->arg20, tactical->arg24, true);
      return true;
    case kControlTagSele: // 'sele'
      battle->LaSelect(unit, true);
      return true;
    default:
      return true;
    }
  }
  case 0x2a: { // resolve a 'fire' action between two units of the live battle
    TacticalCommandPacket* fireCommand = static_cast<TacticalCommandPacket*>(packet);
    TTacticalBattle* fireBattle = g_pActiveTacticalBattle;
    fireBattle->AssertValid();
    TArmyTacUnit* attacker = fireBattle->SeekLinkedListCursorByNestedId(fireCommand->unitId);
    TArmyTacUnit* target = fireBattle->SeekLinkedListCursorByNestedId(fireCommand->arg20);
    if (fireCommand->commandTag != kControlTagFire) {
      return true;
    }
    fireBattle->LaFireOn(attacker, target, target->tileIndex, fireCommand->arg24,
                         fireCommand->arg28, static_cast<char>(fireCommand->arg2C), true);
    break;
  }
  case 0x2b: { // accumulate the presence mask; optionally echo a 0x2b ack
    TurnEvent2BPresenceMaskPacket* presence = static_cast<TurnEvent2BPresenceMaskPacket*>(packet);
    g_nTurnEvent2BNationMaskAccumulator =
        g_nTurnEvent2BNationMaskAccumulator | presence->nationMask;
    if (presence->replyRequestFlag != 0) {
      TurnEvent2BPresenceMaskPacket reply;
      reply.messageTag = kControlTagTime; // 'time'
      reply.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      reply.eventCode = 0;
      reply.eventCode = 0x2b;
      reply.fromNetworkId = 0;
      reply.toNetworkId = 0;
      reply.messageLength = 0;
      reply.replyRequestFlag = 0;
      reply.messageLength = 0x1c;
      reply.nationMask = static_cast<signed char>(g_pSimMgr->GetPlayerCountry());
      reply.toNetworkId = presence->fromNetworkId;
      g_pNetMgr->Send(&reply, false);
    }
    break;
  }
  default:
    return false;
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00549260
TurnEventQueuePacket* TMultiplayerMgr::PopTimelyMessage() {
  TurnEventQueuePacket* packet = primaryTurnEventQueueHead;
  if (packet != 0) {
    primaryTurnEventQueueHead = packet->nextQueuePacket;
  }
  return packet;
}

// FUNCTION: IMPERIALISM 0x00549280
void TMultiplayerMgr::QueueTimelyMessage(TurnEventQueuePacket* node) {
  node->nextQueuePacket = 0;
  TurnEventQueuePacket** tail = &primaryTurnEventQueueHead;
  for (TurnEventQueuePacket* queued = primaryTurnEventQueueHead; queued != 0;
       queued = queued->nextQueuePacket) {
    tail = &queued->nextQueuePacket;
  }
  *tail = node;
}

// FUNCTION: IMPERIALISM 0x005492c0
TurnEventQueuePacket* TMultiplayerMgr::PopVerbalMessage() {
  TurnEventQueuePacket* packet = secondaryTurnEventQueueHead;
  if (packet != 0) {
    secondaryTurnEventQueueHead = packet->nextQueuePacket;
  }
  return packet;
}

// FUNCTION: IMPERIALISM 0x005492e0
void TMultiplayerMgr::QueueVerbalMessage(TurnEventQueuePacket* packet) {
  packet->nextQueuePacket = 0;
  TurnEventQueuePacket** tail = &secondaryTurnEventQueueHead;
  while (*tail != 0) {
    tail = &(*tail)->nextQueuePacket;
  }
  *tail = packet;
}

// FUNCTION: IMPERIALISM 0x00549320
bool TMultiplayerMgr::IsTimelyMessage(NetMessage* packet) {
  switch (packet->eventCode) {
  case 1:
  case 2:
  case 6:
  case 0xa:
  case 0xb:
  case 0xf:
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x2e:
  case 0x2f:
  case 0x30:
    return true;
  default:
    return false;
  }
}

// FUNCTION: IMPERIALISM 0x005493c0
void TMultiplayerMgr::SendMapPoke(signed char pokeWidthCode, TurnEvent11MapOffsetBase mapOffsetBase,
                                  const void* mapEntry, short pokeValue, short pokeMask) {
  TurnEvent11MapPokePacket packet;
  packet.eventCode = 0x11;
  packet.fromNetworkId = 0;
  packet.toNetworkId = (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) ? 0 : -1;
  packet.messageLength = sizeof(packet);
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.pokeWidthCode = pokeWidthCode;
  packet.bufferSelector = mapOffsetBase;
  const void* mapBase = 0;
  if (mapOffsetBase == kTurnEvent11TerrainStateBase) {
    mapBase = g_pGlobalMapState->terrainStateTable;
  } else if (mapOffsetBase == kTurnEvent11CityScoreBase) {
    mapBase = g_pGlobalMapState->cityScoreTable;
  }
  packet.byteOffset = static_cast<const char*>(mapEntry) - static_cast<const char*>(mapBase);
  packet.pokeValue = pokeValue;
  packet.pokeMask = pokeMask;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x005494b0
void TMultiplayerMgr::SendChangeProvinceOwner(short provinceIndex, short nationTag) {
  TurnEvent12Packet packet;
  packet.eventCode = 0x12;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.shortA = provinceIndex;
  packet.shortB = nationTag;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x00549540
void TMultiplayerMgr::SendNewsEvent(int nationSlot, NewsEvent* event) {
  TurnEvent13NewsPacket packet;
  packet.eventCode = 0x13;
  packet.fromNetworkId = 0;
  packet.toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
  packet.messageLength = 0x40;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.nationSlot = static_cast<short>(nationSlot);
  packet.newsEvent = *event;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x005495e0
void TMultiplayerMgr::SendNewsTreatyEvent(short eventKind, unsigned char nationA,
                                          unsigned char nationB) {
  TurnEvent20TreatyNewsPacket packet;
  packet.eventCode = 0x20;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventKind = eventKind;
  packet.nationA = nationA;
  packet.nationB = nationB;
  g_pNetMgr->Send(&packet, true);
}

// FUNCTION: IMPERIALISM 0x00549680
void TMultiplayerMgr::SendNewsShortageEvent(unsigned char subjectNation,
                                            unsigned char affectedNation,
                                            unsigned char relatedNation) {
  TurnEvent21ShortageNewsPacket packet;
  packet.eventCode = 0x21;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.subjectNation = subjectNation;
  packet.affectedNation = affectedNation;
  packet.relatedNation = relatedNation;
  g_pNetMgr->Send(&packet, true);
}

// FUNCTION: IMPERIALISM 0x00549720
void TMultiplayerMgr::SendNewsMiscEvent(unsigned char nationSlotOrAll, short storyCode) {
  TurnEvent22MiscNewsPacket packet;
  packet.eventCode = 0x22;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.nationSlotOrAll = nationSlotOrAll;
  packet.storyCode = storyCode;
  g_pNetMgr->Send(&packet, true);
}

// FUNCTION: IMPERIALISM 0x005497b0
void TMultiplayerMgr::SendTradeOffer(short respondingNation, short offeringNation,
                                     short proposedAmount, short maxAmount, short commodityType) {
  TurnEvent1ANationActionPacket packet;
  packet.eventCode = 0x1a;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x34;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  packet.respondingNation = respondingNation;
  packet.offeringNation = offeringNation;
  packet.proposedAmount = proposedAmount;
  packet.maxAmount = maxAmount;
  packet.commodityType = commodityType;
  for (int nationIndex = 0; nationIndex < kMajorNationCount; ++nationIndex) {
    TGreatPower* nationState = g_apNationStates[nationIndex];
    if (nationState != 0) {
      packet.counterA2BySlot[nationIndex] = nationState->GetMerchantCapacity();
    } else {
      packet.counterA2BySlot[nationIndex] = 0;
    }
  }
  g_pNetMgr->Send(&packet, true);
}

// FUNCTION: IMPERIALISM 0x005498d0
void TMultiplayerMgr::SendDealBookEntry(short nationSlot, short trackedKind, short targetNation,
                                        short trackedValue, short trackedSlotIndex,
                                        int trackedPayload) {
  TurnEvent1BDealBookEntryPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.eventCode = 0x1b;
  packet.messageLength = 0x2c;
  packet.toNetworkId = 0;
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  packet.nationSlot = nationSlot;
  packet.trackedKind = trackedKind;
  packet.targetNation = targetNation;
  packet.trackedValue = trackedValue;
  packet.trackedSlotIndex = trackedSlotIndex;
  packet.trackedPayload = trackedPayload;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x005499b0
void TMultiplayerMgr::SendDealResults(bool broadcast, short sourceNation, short targetNation,
                                      short amount, short maximumAmount, short commodityType,
                                      short shortfallFlag) {
  TurnEvent1CDealResultPacket packet;
  packet.eventCode = 0x1c;
  packet.fromNetworkId = 0;
  packet.toNetworkId = broadcast ? -1 : 0;
  packet.messageLength = sizeof(packet);
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  packet.sourceNation = sourceNation;
  packet.targetNation = targetNation;
  packet.maximumAmount = maximumAmount;
  packet.commodityType = commodityType;
  packet.amount = amount;
  packet.shortfallFlag = shortfallFlag;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x00549a90
void TMultiplayerMgr::SendStreamObject(unsigned long payloadTag, TObject* payloadObject,
                                       int destinationSlot) {
  TaggedSerializablePayload payload;
  payload.tag = payloadTag;
  payload.object = payloadObject;
  SendStreamMessage(0x31, static_cast<short>(destinationSlot), reinterpret_cast<long>(&payload));
}

// FUNCTION: IMPERIALISM 0x00549ad0
void TMultiplayerMgr::SendStreamMessage(short eventTag, short destinationSlot, long payload) {
  TCountingStream* counter = new TCountingStream();
  counter->ICountingStream();
  WriteMessageTo(counter, eventTag, destinationSlot, payload);
  int packetBytes = counter->GetPosition();
  counter->Free();
  HGLOBAL packetMemory = GlobalAlloc(GMEM_MOVEABLE, packetBytes);
  THandleStream* writer = new THandleStream();
  writer->IHandleStream(packetMemory, 0x10);
  WriteMessageTo(writer, eventTag, destinationSlot, payload);
  NetMessage* packet = static_cast<NetMessage*>(GlobalLock(packetMemory));
  packet->messageLength = writer->GetPosition();
  writer->Free();
  g_pNetMgr->Send(packet, destinationSlot == -3);
  GlobalFree(packetMemory);
}

// FUNCTION: IMPERIALISM 0x00549c60
void TMultiplayerMgr::WriteMessageTo(TStream* stream, short eventTag, short destinationSlot,
                                     long payload) {
  TimelyNetMessagePrefix header;
  header.messageTag = kControlTagTime;
  header.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  int tag = eventTag;
  header.eventCode = 0;
  header.fromNetworkId = 0;
  header.messageLength = 0x1c;
  header.eventCode = tag;
  int dest = destinationSlot;
  header.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  if (dest == -2 || dest == -3) {
    header.toNetworkId = 0;
  } else if (dest == -1) {
    header.toNetworkId = -1;
  } else {
    header.toNetworkId = g_pGameFlowState->nationSessionIds[dest];
  }
  stream->WriteBytes(&header, 0x1c);
  StreamMessagePayload32 payloadValue;
  payloadValue.scalarValue = payload;
  switch (tag) {
  case 0x2e:
    g_pNavyOrderManager->WriteToFilterously(stream, static_cast<short>(payloadValue.scalarValue));
    return;
  case 0x2f:
    WriteArmyUnitsTo(stream, payloadValue.scalarValue);
    return;
  case 0x30:
    WriteCiviliansTo(stream, payloadValue.scalarValue);
    return;
  case 0x31: {
    TaggedSerializablePayload* record = reinterpret_cast<TaggedSerializablePayload*>(payload);
    stream->WriteLong(record->tag);
    if (record->tag != kControlTagStar) { // 'star'
      record->object->WriteTo(stream);
      return;
    }
    TTurnStartEvent* event = static_cast<TTurnStartEvent*>(record->object);
    event->AssertValid();
    stream->WriteLong(event->eventTag);
    if (event->eventTag == kControlTagLand) { // 'land'
      TLandSaleEvent* landSale = static_cast<TLandSaleEvent*>(event);
      landSale->AssertValid();
      stream->WriteInteger(landSale->tileIndex);
      stream->WriteInteger(landSale->nationCode);
      return;
    }
  } break;
  case 0x28:
    reinterpret_cast<TObject*>(payload)->WriteTo(stream);
    return;
  case 0x32:
    g_pTradeMgr->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x00549f10
void TMultiplayerMgr::ReceiveStreamMessage(NetMessage* packet) {
  g_nSaveFormatVersion = kSessionTagNetX;

  unsigned long packetBytes = packet->messageLength;
  HGLOBAL packetBlock = ::GlobalAlloc(GMEM_MOVEABLE, packetBytes);
  void* blockBytes = ::GlobalLock(packetBlock);
  memmove(blockBytes, packet, packetBytes);
  ::GlobalUnlock(packetBlock);

  THandleStream* stream = new THandleStream();
  stream->IHandleStream(packetBlock, 0x10);
  ReadMessageFrom(stream);
  stream->Free();

  g_nSaveFormatVersion = -1;
}

// FUNCTION: IMPERIALISM 0x00549ff0
void TMultiplayerMgr::ReadMessageFrom(TStream* stream) {
  TimelyNetMessagePrefix header;
  header.messageTag = kControlTagTime;
  header.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  stream->ReadBytes(&header, 0x1c);
  bool isClientSession = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
  short nation;
  if (isClientSession) {
    nation = -1;
  } else {
    nation = static_cast<char>(header.activeNationId);
  }
  switch (header.eventCode) {
  case 0x2e:
    g_pNavyOrderManager->ReadFromFilterously(stream, nation);
    g_pActiveMapOrderContext->UpdateOccupants();
    break;
  case 0x2f:
    ReadArmyUnitsFrom(stream, nation);
    break;
  case 0x30:
    ReadCiviliansFrom(stream, nation);
    break;
  case 0x31: {
    int payloadTag = stream->ReadLong();
    if (payloadTag != kControlTagArmy) {     // 'army'
      if (payloadTag != kControlTagStar) {   // 'star'
        if (payloadTag == kControlTagTown) { // 'town'
          TTown* town = new TTown();
          town->ITown(g_szEmptyString, 0, false, g_pSimMgr->GetPlayerCountry());
          town->ReadFrom(stream);
          TTown* existing = g_pGlobalMapState->GetTown(town->tileIndex);
          if (existing != 0) {
            memcpy(existing, town, sizeof(TTown));
            town->Free();
          } else {
            g_apNationStates[town->ownerNation]->townMarkerList->AddTail(town);
          }
        }
      } else {
        if (stream->ReadLong() == kControlTagLand) { // 'land'
          short tileIndex = stream->ReadInteger();
          short nationCode = stream->ReadInteger();
          TLandSaleEvent* saleEvent = new TLandSaleEvent();
          saleEvent->ILandSaleEvent(tileIndex, nationCode);
          g_apNationStates[static_cast<short>(g_pSimMgr->GetPlayerCountry())]->AddTurnStartEvent(
              saleEvent);
        }
      }
    } else {
      g_pMapContextActionManager->ReadFrom(stream);
    }
    break;
  }
  case 0x28: {
    TArmyBattle* battle = new TArmyBattle();
    battle->ReadFrom(stream);
    battle->StartBattle();
    break;
  }
  case 0x32:
    g_pTradeMgr->ReadFrom(stream);
    g_apNationStates[static_cast<short>(g_pSimMgr->GetPlayerCountry())]->InitializeDealBook();
    break;
  default:
    break;
  }
}
IMPERIALISM_END_RETAIL_POLYMORPHIC_BYTE_COPY

// FUNCTION: IMPERIALISM 0x0054a340
void TMultiplayerMgr::SendGameControl(int statusTag, int value, int nationSlotOrMode) {
  TurnEvent1FStatusPacket packet;
  packet.eventCode = 0x1f;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.statusTag = statusTag;
  packet.controlValue = value;
  if ((nationSlotOrMode == -2) || (nationSlotOrMode == -3)) {
    packet.toNetworkId = 0;
  } else if (nationSlotOrMode == -1) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[nationSlotOrMode];
  }
  g_pNetMgr->Send(&packet, nationSlotOrMode == -3);
}

// FUNCTION: IMPERIALISM 0x0054a410
void TMultiplayerMgr::DispatchLobbyTextPairEvent8(unsigned char sourceNationSlot) {
  LobbyTextPairEvent8Packet packet;
  packet.messageTag = kControlTagTime; // 'time'
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.eventCode = 8;
  packet.messageLength = 0;
  packet.messageLength = 0x5c;
  packet.toNetworkId = -1;
  packet.sourceNationSlot = sourceNationSlot;
  strcpy(packet.playerName, static_cast<LPCSTR>(playerNameString));
  strcpy(packet.playerNameMirror, static_cast<LPCSTR>(playerNameMirror));
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054a500
void TMultiplayerMgr::WriteArmyUnitsTo(TStream* stream, int terrainSlot) {
  stream->WriteByte(static_cast<unsigned char>(terrainSlot + 'a'));
  TCountry* descriptor = g_apTerrainTypeDescriptorTable[terrainSlot];
  if (descriptor == 0) {
    stream->WriteInteger(0);
  } else {
    stream->WriteInteger(descriptor->militaryUnitList->GetCount());
    CIterator unitIter(descriptor->militaryUnitList);
    for (TObject* unit = static_cast<TObject*>(unitIter.Reset()); unitIter.More();
         unit = static_cast<TObject*>(unitIter.Advance())) {
      unit->WriteTo(stream);
    }
  }
  stream->WriteByte('.');
}

// FUNCTION: IMPERIALISM 0x0054a5e0
void TMultiplayerMgr::WriteCiviliansTo(TStream* stream, int nationFilter) {
  for (int slot = 0; slot < 7; ++slot) {
    bool matches;
    if (nationFilter == -1 || nationFilter == slot) {
      matches = true;
    } else {
      matches = false;
    }
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0 || !matches) {
      stream->WriteInteger(0);
    } else {
      stream->WriteInteger(nation->trackedObjectList->GetCount());
      CIterator trackedIter(nation->trackedObjectList);
      for (TObject* tracked = static_cast<TObject*>(trackedIter.Reset()); trackedIter.More();
           tracked = static_cast<TObject*>(trackedIter.Advance())) {
        tracked->WriteTo(stream);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054a6d0
void TMultiplayerMgr::ReadArmyUnitsFrom(TStream* stream, short nationSlot) {
  int terrainSlot = stream->ReadByte() - 0x61; // - 'a'
  const bool terrainSelected = nationSlot == -1 || nationSlot == terrainSlot;
  if (terrainSelected) {
    if (g_apTerrainTypeDescriptorTable[terrainSlot] != 0) {
      CIterator recruitIter(g_apTerrainTypeDescriptorTable[terrainSlot]->militaryUnitList);
      for (TUnit* pendingRecruit = static_cast<TUnit*>(recruitIter.Reset()); recruitIter.More();
           pendingRecruit = static_cast<TUnit*>(recruitIter.Advance())) {
        pendingRecruit->Vaporize();
      }
      g_apTerrainTypeDescriptorTable[terrainSlot]->militaryUnitList->FreePayloads();
    }
    short recruitOrderCount = stream->ReadInteger();
    for (int recruitOrderIdx = recruitOrderCount; recruitOrderIdx != 0; --recruitOrderIdx) {
      TMilitaryUnit* recruitOrder = new TMilitaryUnit();
      recruitOrder->IMilitaryUnit(0, -1, static_cast<short>(terrainSlot), 0);
      recruitOrder->ReadFrom(stream);
      recruitOrder->AssertValid();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054a840
void TMultiplayerMgr::ReadCiviliansFrom(TStream* stream, short nationSlot) {
  for (int nationIdx = 0; nationIdx < kMajorNationCount; ++nationIdx) {
    const bool nationSelected = nationSlot == -1 || nationSlot == nationIdx;
    if (g_apNationStates[nationIdx] != 0 && nationSelected) {
      CIterator workOrderIter(g_apNationStates[nationIdx]->trackedObjectList);
      for (TUnit* pendingWorkOrder = static_cast<TUnit*>(workOrderIter.Reset());
           workOrderIter.More(); pendingWorkOrder = static_cast<TUnit*>(workOrderIter.Advance())) {
        pendingWorkOrder->Vaporize();
      }
      g_apNationStates[nationIdx]->trackedObjectList->FreePayloads();
    }
    short workOrderCount = stream->ReadInteger();
    for (int workOrderIdx = workOrderCount; workOrderIdx != 0; --workOrderIdx) {
      TCivUnit* workOrder = new TCivUnit();
      workOrder->ICivUnit(kCivilianUnitMiner, -1, nationIdx);
      workOrder->ReadFrom(stream);
      workOrder->AssertValid();
      if (!nationSelected) {
        workOrder->Vaporize();
        workOrder->Free();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054a9d0
int TMultiplayerMgr::IsSpecialNationDialogModeActive() {
  if (sessionPhaseTag == kSessionTagGoin) {
    if (g_pSimMgr->GetPlayerCountry() != -1) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0054aa10
void TMultiplayerMgr::SendVerbalMessage(CString* text, unsigned char firstFlag,
                                        unsigned char secondFlag) {
  TurnEventCKickMessagePacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.eventCode = 0xc;
  packet.toNetworkId = 0;
  packet.targetNationBitmask = 0xff;
  packet.messageLength = 0;
  packet.messageLength = 0x11c;
  packet.kickerNationId = static_cast<signed char>(g_pSimMgr->GetPlayerCountry());
  strcpy(packet.messageText, static_cast<LPCSTR>(*text));
  packet.eventCode = 0xc;
  packet.targetNationBitmask = firstFlag;
  packet.kickerNationId = secondFlag;
  packet.toNetworkId = 0;
  g_pNetMgr->Send(&packet, true);
}

// FUNCTION: IMPERIALISM 0x0054ab20
extern "C" void __stdcall SendTileNews(short tileIndex) {
  TurnEvent23TileStatePacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0x23;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  packet.tileIndex = tileIndex;
  packet.record = g_pGlobalMapState->terrainStateTable[tileIndex];
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054abf0
void TMultiplayerMgr::DispatchCityRedrawInvalidateEvent(short cityId) {
  TurnEvent24CityRecordPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0x24;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  packet.cityRecordIndex = cityId;
  packet.record = g_pGlobalMapState->cityScoreTable[cityId];
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054b1b0
void TMultiplayerMgr::PoseMessageDialog(int unused) {
  FindActiveNationSlotIndexInGameFlowList();
  int mySlotIndex = FindActiveNationSlotIndexInGameFlowList();
  if (mySlotIndex == -1) {
    CString notSeatedMessage;
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&notSeatedMessage, 0x2742, 0x16);
    g_pViewMgr->ModalMessage(notSeatedMessage, g_ptNationAwolModalMessage, 0, 0);
    return;
  }

  TView* dialog =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventJoinSelectorMessage);
  if (dialog == 0) {
    FailNilPointerWithAssert(s_SourcePathUMultiplayerMgr, 0x1061);
  }

  for (int i = 0; i < 7; ++i) {
    TMadnessButton* boxControl =
        static_cast<TMadnessButton*>(dialog->FindSubView(kSessionTagBox0 + i));
    boxControl->AssertValid();
    int sessionId = g_pGameFlowState->nationSessionIds[i];
    bool occupied = sessionId != 0 && sessionId != -2;
    bool isMine = g_pNetMgr->GetPlayerID() == g_pGameFlowState->nationSessionIds[i];
    bool occupiedByOther = occupied && !isMine;
    static_cast<TView*>(boxControl)->ViewEnable(static_cast<int>(occupiedByOther), 0);
    if (mySlotIndex != -1) {
      boxControl->SetState(static_cast<unsigned char>(i == mySlotIndex),
                           static_cast<unsigned char>(0));
    } else {
      boxControl->SetState(static_cast<unsigned char>(occupiedByOther),
                           static_cast<unsigned char>(0));
    }
    boxControl->CheckTheLook(0);
  }

  TextStyle messageStyle;
  BuildUiTextStyleDescriptor(&messageStyle, 0, 0xc, 0);
  TStaticText* messageControl =
      static_cast<TStaticText*>(dialog->FindSubView(kSessionTagMesg)); // 'mesg'
  messageControl->AssertValid();
  messageControl->InstallTextStyle(messageStyle, 0);
  messageControl->BecomeTarget();
  dialog->Open();
}

// FUNCTION: IMPERIALISM 0x0054b4c0
void TMultiplayerMgr::SendGpSelection(int reasonCode, int field1CValue, const char* senderText,
                                      const char* messageText) {
  LobbyChatEvent9Packet packet;
  packet.eventCode = 9;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = sizeof(packet);
  packet.InitializeEmitEventHeaderWithActiveNation();
  packet.nationSlot = static_cast<unsigned char>(reasonCode);
  packet.sessionId = field1CValue;
  strcpy(packet.senderName, senderText);
  strcpy(packet.messageText, messageText);
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054b5b0
void TMultiplayerMgr::SendTradeBook() {
  SendStreamMessage(0x32, -2, 0);
}

// FUNCTION: IMPERIALISM 0x0054b5d0
void TMultiplayerMgr::SendBankStatement(bool broadcastFlag, int nationSlot) {
  TurnEvent15Packet packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.eventCode = 0x15;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.messageLength = 0x6e4;
  if (broadcastFlag) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
  }
  packet.nationSlot = static_cast<short>(nationSlot);
  TGreatPower* nation = g_apNationStates[nationSlot];
  packet.treasuryValue = nation->treasuryValue;
  packet.grantTotalCost = nation->grantTotalCost;
  for (int i = 0; i < 0x17; ++i) {
    packet.needCurrentByType[i] = nation->needCurrentByType[i];
    packet.needTargetByType[i] = nation->needTargetByType[i];
    packet.relationDeltaCurrent[i] = nation->relationDeltaCurrent[i];
    packet.purchasedItemsByResource[i] = nation->purchasedItemsByResource[i];
    packet.itemPotentials[i] = nation->itemPotentials[i];
    for (int j = 0; j < 0x10; ++j) {
      packet.aidAllocationMatrix[j * 0x17 + i] = nation->aidAllocationMatrix[j * 0x17 + i];
    }
  }
  packet.budgetPoolBase = nation->budgetPoolBase;
  packet.budgetPoolDelta = nation->budgetPoolDelta;
  packet.diplomacyBudgetBase = nation->diplomacyBudgetBase;
  packet.escalationCounter = nation->escalationCounter;
  packet.pendingCommitmentCost = nation->pendingCommitmentCost;
  packet.pressureCounter = nation->pressureCounter;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054b7e0
void TMultiplayerMgr::SetPlayerStatus(int statusTag, int nationSlot) {
  if (nationSlot == -1) {
    nationSlot = g_pSimMgr->GetPlayerCountry();
    if (nationSlot == -1) {
      nationSlot = static_cast<signed char>(activeNationTagIndex);
    }
  }
  nationStatusTags[nationSlot] = statusTag;

  NationStatusEvent25Packet packet;
  packet.messageTag = kControlTagTime; // 'time'
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.eventCode = 0x25;
  packet.messageLength = 0;
  packet.messageLength = 0x34;
  for (int slot = 0; slot < kMajorNationSessionSlotCount; ++slot) {
    packet.statusTags[slot] = kSessionTagUnkn; // 'unkn'
  }
  packet.toNetworkId = 0;
  packet.statusTags[nationSlot] = statusTag;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054b8c0
int TMultiplayerMgr::GetPlayerStatus(int slot) {
  if (slot == -1) {
    slot = g_pSimMgr->GetPlayerCountry();
    if (slot == -1) {
      int sessionActive = g_pNetMgr->GetPlayerID();
      slot = 0;
      int* sessionId = g_pGameFlowState->nationSessionIds;
      while (slot < 7 && *sessionId != sessionActive) {
        ++slot;
        ++sessionId;
      }
      if (slot == 7) {
        slot = -1;
      }
    }
  }
  return nationStatusTags[slot];
}

// FUNCTION: IMPERIALISM 0x0054b930
void TMultiplayerMgr::WeLostAClient(int networkId) {
  for (int slot = 0; slot < 7; ++slot) {
    if (nationSessionIds[slot] == networkId) {
      int tagSlot = slot;
      if (slot == -1) {
        tagSlot = g_pSimMgr->GetPlayerCountry();
      }
      if (tagSlot == -1) {
        tagSlot = activeNationTagIndex;
      }
      nationStatusTags[tagSlot] = kSessionTagAwol; // 'awol'
      NationStatusEvent25Packet statusPacket;
      statusPacket.InitializeEmitEventHeaderWithActiveNation();
      statusPacket.InitializeNationStatusEvent25PayloadDefaults();
      statusPacket.toNetworkId = 0;
      statusPacket.statusTags[tagSlot] = kSessionTagAwol;
      g_pNetMgr->Send(&statusPacket, false);
      nationSessionIds[slot] = -2;
      pendingNationBitmask |= 1 << slot;
      if (sessionPhaseTag == kSessionTagInit &&
          g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) { // 'init'
        LobbyChatEvent9Packet chat;
        chat.InitializeEmitEventHeaderWithActiveNation();
        chat.eventCode = 0;
        chat.sessionId = 0;
        chat.fromNetworkId = 0;
        chat.eventCode = 9;
        chat.toNetworkId = 0;
        chat.messageLength = 0;
        chat.messageLength = 0x64;
        chat.nationSlot = static_cast<unsigned char>(slot);
        strcpy(chat.senderName, g_szEmptyString);
        strcpy(chat.messageText, g_szEmptyString);
        g_pNetMgr->Send(&chat, true);
      } else {
        CString formatted;
        CString nationName;
        nationName = defaultNationTextSlots[slot];
        CString templateText;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&templateText, 0x2759, 4);
        scanBracketExpressions(g_pSimMgr, &formatted, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationName));
        g_pViewMgr->ModalMessage(formatted, g_ptNationAwolModalMessage, 0, 0);
        if (g_pGameFlowState != this || networkSavePending == 0) {
          TCancelGameOptionsCommand* cancelCommand = new TCancelGameOptionsCommand();
          cancelCommand->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0,
                                  0); // 'pogc'
          g_pAmbitApplication->DispatchUiSelectionToHandler(cancelCommand);
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054bce0
void NationStatusEvent25Packet::InitializeNationStatusEvent25PayloadDefaults() {
  NetMessage* header = this;
  header->eventCode = 0;
  header->fromNetworkId = 0;
  header->toNetworkId = 0;
  header->messageLength = 0;
  messageLength = 0x34;
  eventCode = 0x25;
  for (int slot = 0; slot < 7; ++slot) {
    statusTags[slot] = kSessionTagUnkn; // 'unkn'
  }
}

// FUNCTION: IMPERIALISM 0x0054bd20
void TMultiplayerMgr::DehumanizePlayer(int nationSlot) {
  bool isLocalNation = nationSlot == g_pSimMgr->GetPlayerCountry();
  MultiplayerSessionRole sessionRole = g_pSimMgr->multiplayerSessionRole;
  bool isClientSession = sessionRole == kSessionRoleClient;
  if (!isClientSession) {
    bool hosting = sessionRole == kSessionRoleHost;
    if (hosting) {
      TurnEvent1FStatusPacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.eventCode = 0x1f;
      packet.messageLength = 0;
      packet.messageLength = 0x20;
      packet.DestinateTo(-2);
      packet.statusTag = kSessionTagDehu; // 'uhed'
      packet.controlValue = nationSlot;
      g_pNetMgr->Send(&packet, false);
    }
    TGreatPower* oldNation = g_apNationStates[nationSlot];
    if (oldNation != 0 && oldNation->diplomacyEligibility != 0 && !isLocalNation) {
      int policyDice5 = rand() % 5;
      int policyDice6 = rand() % 6;
      int policyDice4 = rand() % 4;
      TAutoGreatPower* newNation = new TAutoGreatPower();
      newNation->IAutoGreatPower(nationSlot, 2, static_cast<short>(policyDice4),
                                 static_cast<short>(policyDice6), static_cast<short>(policyDice5));

      newNation->identitySharedString0 = oldNation->identitySharedString0;
      newNation->identitySharedString1 = oldNation->identitySharedString1;
      newNation->nationSlot = oldNation->nationSlot;
      newNation->encodedNationSlot = oldNation->encodedNationSlot;
      newNation->treasuryValue = oldNation->treasuryValue;
      memcpy(newNation->tradePolicyByNation, oldNation->tradePolicyByNation,
             sizeof(newNation->tradePolicyByNation));
      TSortedList* militaryUnits = newNation->militaryUnitList;
      newNation->militaryUnitList = oldNation->militaryUnitList;
      oldNation->militaryUnitList = militaryUnits;
      memcpy(newNation->unitNameOrdinalByType, oldNation->unitNameOrdinalByType,
             sizeof(newNation->unitNameOrdinalByType));
      newNation->unitNameCounter = oldNation->unitNameCounter;
      newNation->homeTileIndex = oldNation->homeTileIndex;
      newNation->overlayAnchorTileCache = oldNation->overlayAnchorTileCache;
      TLongintList* ownedRegions = newNation->ownedRegionList;
      newNation->ownedRegionList = oldNation->ownedRegionList;
      oldNation->ownedRegionList = ownedRegions;
      newNation->availableMerchantCapacity = oldNation->availableMerchantCapacity;
      newNation->merchantCapacity = oldNation->merchantCapacity;
      newNation->transportCapacity = oldNation->transportCapacity;
      newNation->reservedTransportCapacity = oldNation->reservedTransportCapacity;
      newNation->grantTotalCost = oldNation->grantTotalCost;
      newNation->unfilledTradeOfferCount = oldNation->unfilledTradeOfferCount;
      memcpy(newNation->diplomacyPolicyByNation, oldNation->diplomacyPolicyByNation,
             sizeof(newNation->diplomacyPolicyByNation));
      memcpy(newNation->diplomacyGrantByNation, oldNation->diplomacyGrantByNation,
             sizeof(newNation->diplomacyGrantByNation));
      memcpy(newNation->needCurrentByType, oldNation->needCurrentByType,
             sizeof(newNation->needCurrentByType));
      memcpy(newNation->needTargetByType, oldNation->needTargetByType,
             sizeof(newNation->needTargetByType));
      memcpy(newNation->relationDeltaCurrent, oldNation->relationDeltaCurrent,
             sizeof(newNation->relationDeltaCurrent));
      memcpy(newNation->purchasedItemsByResource, oldNation->purchasedItemsByResource,
             sizeof(newNation->purchasedItemsByResource));
      memcpy(newNation->itemPotentials, oldNation->itemPotentials,
             sizeof(newNation->itemPotentials));
      memcpy(newNation->unfilledTradeTurnCountsByResource,
             oldNation->unfilledTradeTurnCountsByResource,
             sizeof(newNation->unfilledTradeTurnCountsByResource));
      memcpy(newNation->transportedItemsByResource, oldNation->transportedItemsByResource,
             sizeof(newNation->transportedItemsByResource));
      memcpy(newNation->rememberedTradeOffersByResource, oldNation->rememberedTradeOffersByResource,
             sizeof(newNation->rememberedTradeOffersByResource));
      memcpy(newNation->aidAllocationMatrix, oldNation->aidAllocationMatrix,
             sizeof(newNation->aidAllocationMatrix));
      newNation->budgetPoolBase = oldNation->budgetPoolBase;
      newNation->budgetPoolDelta = oldNation->budgetPoolDelta;
      TPtrList* turnEvents = newNation->turnEventQueue;
      newNation->turnEventQueue = oldNation->turnEventQueue;
      oldNation->turnEventQueue = turnEvents;
      TPtrList* proposals = newNation->proposalQueue;
      newNation->proposalQueue = oldNation->proposalQueue;
      oldNation->proposalQueue = proposals;
      for (int trackedSlot = 0; trackedSlot < 0x11; ++trackedSlot) {
        TPtrList* tracked = newNation->diplomacyTrackedSlots[trackedSlot];
        newNation->diplomacyTrackedSlots[trackedSlot] =
            oldNation->diplomacyTrackedSlots[trackedSlot];
        oldNation->diplomacyTrackedSlots[trackedSlot] = tracked;
      }
      TCity* city = oldNation->city;
      oldNation->city = newNation->city;
      newNation->city = city;
      if (city != 0) {
        city->ownerNation = newNation;
      }
      TSortedList* townMarkers = newNation->townMarkerList;
      newNation->townMarkerList = oldNation->townMarkerList;
      oldNation->townMarkerList = townMarkers;
      TSortedList* trackedObjects = newNation->trackedObjectList;
      newNation->trackedObjectList = oldNation->trackedObjectList;
      oldNation->trackedObjectList = trackedObjects;
      memcpy(newNation->enemyFlags, oldNation->enemyFlags, sizeof(newNation->enemyFlags));
      memcpy(&newNation->pendingActionStatus, &oldNation->pendingActionStatus,
             sizeof(newNation->pendingActionStatus));
      memcpy(newNation->field8d6, oldNation->field8d6, sizeof(newNation->field8d6));
      newNation->armyTransportRemaining = oldNation->armyTransportRemaining;
      newNation->turnFinished = oldNation->turnFinished;

      g_apNationStates[nationSlot] = newNation;
      g_apTerrainTypeDescriptorTable[nationSlot] = newNation;
      newNation->CreateInitialMissions();
      for (int targetSlot = 0; targetSlot < kNationSlotCount; ++targetSlot) {
        if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, targetSlot)) {
          newNation->enemyFlags[targetSlot] = 1;
        }
      }
      g_pSimMgr->nationControlModes[nationSlot] = 2;
      oldNation->Free();
    }
    bool stillHosting = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (stillHosting && !isLocalNation) {
      g_pNetMgr->NotifyIfNationMatchesSessionActiveNation(nationSessionIds[nationSlot]);
    }
  }
  bool tornDownNow = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
  if (tornDownNow) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0) {
      nation->diplomacyEligibility = 0;
    }
  }
  nationSessionIds[nationSlot] = 0;
  nationStatusTags[nationSlot] = kSessionTagUnas; // 'suna'
  RecalcPlayerName(nationSlot);
  bool hostingMask = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
  if (hostingMask) {
    pendingNationBitmask &= ~(1 << nationSlot);
    bool hostingBroadcast = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
    if (hostingBroadcast) {
      TurnEvent1PendingMaskPacket packet;
      packet.messageTag = kControlTagTime;
      packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
      packet.eventCode = 0;
      packet.fromNetworkId = 0;
      packet.toNetworkId = 0;
      packet.eventCode = 1;
      packet.messageLength = 0;
      packet.messageLength = 0x1c;
      packet.toNetworkId = 0;
      packet.pendingMask = pendingNationBitmask;
      g_pNetMgr->Send(&packet, false);
      if (pendingNationBitmask == 0 && syncPhase != kGamePhaseNone) {
        HandleDiplomacyTurnEventPacketByCode();
      }
    }
  }
}
// FUNCTION: IMPERIALISM 0x0054c480
void TMultiplayerMgr::EmitTurnEvent26DiplomacyMatrixSnapshot() {
  TurnEvent26DiplomacyMatrixPacket packet;
  packet.messageTag = kControlTagTime; // 'time'
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.eventCode = 0x26;
  packet.messageLength = 0x814;
  memcpy(packet.relationCodeMatrix, g_pDiplomacyTurnStateManager->relationCodeMatrix,
         sizeof(packet.relationCodeMatrix));
  memcpy(packet.pendingPolicyCodeMatrix, g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix,
         sizeof(packet.pendingPolicyCodeMatrix));
  memcpy(packet.pendingPolicyTierMatrix, g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix,
         sizeof(packet.pendingPolicyTierMatrix));
  packet.congressLeadership.chairmanNationSlot =
      g_pDiplomacyTurnStateManager->congressLeadership.chairmanNationSlot;
  packet.congressLeadership.counterpartNationSlot =
      g_pDiplomacyTurnStateManager->congressLeadership.counterpartNationSlot;
  packet.congressSupport.chairmanSupportCount =
      g_pDiplomacyTurnStateManager->congressSupport.chairmanSupportCount;
  packet.congressSupport.counterpartSupportCount =
      g_pDiplomacyTurnStateManager->congressSupport.counterpartSupportCount;
  packet.congressSupport.neutralCount = g_pDiplomacyTurnStateManager->congressSupport.neutralCount;
  memcpy(packet.relationTailBlock, g_pDiplomacyTurnStateManager->comparativePowerRows,
         sizeof(packet.relationTailBlock));
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054c5a0
void TMultiplayerMgr::SendChangeMaster(int sourceNation, int targetNation, int mode) {
  TurnEvent27JoinEmpirePacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.terrainSlot = sourceNation;
  packet.targetNationSlot = targetNation;
  packet.mode = mode;
  packet.messageLength = 0x24;
  packet.eventCode = 0x27;
  g_pNetMgr->Send(&packet, false);
}

// FUNCTION: IMPERIALISM 0x0054c630
void TMultiplayerMgr::SetDialogModeTagInitAndInvokeNoOpHook() {
  sessionPhaseTag = kSessionTagInit; // 'init'
  g_pNetMgr->NoOpDialogModeTagChangedHook(1);
}

// FUNCTION: IMPERIALISM 0x0054c660
void TMultiplayerMgr::NoOpCallbackRet4(void* param) {}

// FUNCTION: IMPERIALISM 0x0054c680
void TMultiplayerMgr::SendTacLa(int commandTag, TTacticalUnit* unit, int arg3, int arg4) {}

// FUNCTION: IMPERIALISM 0x0054c6a0
void TMultiplayerMgr::SendTacLaEx(int commandTag, TTacticalUnit* attackerUnit,
                                  TTacticalUnit* targetUnit, int damageA, int damageB,
                                  int effectCode) {}

// FUNCTION: IMPERIALISM 0x0054c6c0
void TMultiplayerMgr::SendTacticalBattle(TTacticalBattle* battle) {
  battle->StartBattle();
}

// FUNCTION: IMPERIALISM 0x0054c6e0
void TMultiplayerMgr::ResetNationStatusArraysAndTurnEventContext() {
  CString statusText;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&statusText, 0x2759, 1);
  for (int nationSlot = 0; nationSlot < kMajorNationSessionSlotCount; ++nationSlot) {
    nationSessionIds[nationSlot] = 0;
    nationStatusTags[nationSlot] = kSessionTagUnas; // 'suna'
    nationDisplayNameSlots[nationSlot] = statusText;
    defaultNationTextSlots[nationSlot] = nationDisplayNameSlots[nationSlot];
  }
  resumePhase = kGamePhaseNone;
  syncPhase = kGamePhaseNone;
  queueSyncDword = 0;
  g_pNetMgr->ResetTurnEventQueueRuntimeRecordBuffer();
}

// FUNCTION: IMPERIALISM 0x0054c7d0
void TMultiplayerMgr::DiscardPlayer(int nationId) {
  g_pNetMgr->NotifyIfNationMatchesSessionActiveNation(nationId);
}

// FUNCTION: IMPERIALISM 0x0054c800
bool TMultiplayerMgr::HandleActiveNationAwolTransitionOrRecovery() {
  int activeNation = g_pSimMgr->GetPlayerCountry();
  nationSessionIds[activeNation] = -2;
  if (g_pNetMgr->CheckConnectivityOrShowLocalizedWarningAndReturnReady()) {
    int sessionNation = g_pNetMgr->GetPlayerID();
    activeNation = g_pSimMgr->GetPlayerCountry();
    nationSessionIds[activeNation] = sessionNation;
    return true;
  }

  activeNation = g_pSimMgr->GetPlayerCountry();
  nationStatusTags[activeNation] = kSessionTagAwol;                                // 'awol'
  if (sessionPhaseTag == kSessionTagGoin && g_pSimMgr->GetPlayerCountry() != -1) { // 'goin'
    g_pAmbitApplication->CreateAndQueueTurnEventPacketTagGWEN();
    return false;
  }
  CreateAndQueueTurnEventPacketTagPOGC();
  return false;
}

// FUNCTION: IMPERIALISM 0x0054c8e0
void TMultiplayerMgr::EmitTurnEventEAnd9SessionContextPackets(NetMessage* packet) {
  if (g_pGlobalMapState == 0 || sessionPhaseTag == kSessionTagPrep) {
    return;
  }
  {
    TurnEventESessionInitPacket sessionInit;
    sessionInit.messageTag = kControlTagTime; // 'time'
    sessionInit.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
    sessionInit.eventCode = 0;
    sessionInit.eventCode = 0xe;
    sessionInit.fromNetworkId = 0;
    sessionInit.toNetworkId = 0;
    sessionInit.messageLength = 0;
    sessionInit.messageLength = 0x68;
    if (packet != 0) {
      sessionInit.toNetworkId = packet->fromNetworkId;
    } else {
      sessionInit.toNetworkId = 0;
    }
    sessionInit.scenarioTag = scenarioSelectionTag;
    bool resumingSavedGame;
    if (sessionPhaseTag == kSessionTagGoin && g_pSimMgr->GetPlayerCountry() != -1) {
      resumingSavedGame = true;
    } else {
      resumingSavedGame = false;
    }
    if (resumingSavedGame) {
      sessionInit.scenarioTag = kControlTagLoad; // 'load'
    }
    strcpy(sessionInit.hostGameName, gameNameString);
    strcpy(sessionInit.mapSeedText, g_pGlobalMapState->scenarioTagText);
    sessionInit.mapParamByte39 = g_pGlobalMapState->hexNeighborWrapHorizontally;
    sessionInit.saveSlotDword5C = queueSyncDword;
    sessionInit.difficultyLevel = static_cast<signed char>(g_pSimMgr->difficultyLevel);
    sessionInit.nameTableFlag = g_pSimMgr->useLocalizedNameTables;
    g_pNetMgr->Send(&sessionInit, false);
  }
  {
    LobbyChatEvent9Packet seatClaim;
    seatClaim.messageTag = kControlTagTime; // 'time'
    seatClaim.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
    seatClaim.eventCode = 0;
    seatClaim.eventCode = 9;
    seatClaim.fromNetworkId = 0;
    seatClaim.toNetworkId = 0;
    seatClaim.messageLength = 0;
    seatClaim.messageLength = 0x64;
    if (packet != 0) {
      seatClaim.toNetworkId = packet->fromNetworkId;
    } else {
      seatClaim.toNetworkId = 0;
    }
    for (int emitSlot = 0; emitSlot < 7; ++emitSlot) {
      seatClaim.sessionId = nationSessionIds[emitSlot];
      seatClaim.nationSlot = static_cast<unsigned char>(emitSlot);
      strcpy(seatClaim.senderName, defaultNationTextSlots[emitSlot]);
      strcpy(seatClaim.messageText, nationDisplayNameSlots[emitSlot]);
      g_pNetMgr->Send(&seatClaim, false);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054cb80
bool TMultiplayerMgr::WaitForClients() {
  return g_pNetMgr->Ping() == 0;
}

// FUNCTION: IMPERIALISM 0x0054cbb0
bool TMultiplayerMgr::AreAllSessionSlotsOwnedByActiveNation() {
  for (int slot = 0; slot < kMajorNationSessionSlotCount; ++slot) {
    if (nationSessionIds[slot] != 0 && nationSessionIds[slot] != -2 &&
        nationSessionIds[slot] != g_pNetMgr->GetPlayerID()) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x0054cc00
void TMultiplayerMgr::RecalcPlayerName(int nationSlot) {
  if (nationSlot == -1) {
    for (int slot = 0; slot < 7; ++slot) {
      RecalcPlayerName(slot);
    }
  } else if (g_apNationStates[nationSlot] == 0) {
    {
      CString emptyName(g_szEmptyString);
      defaultNationTextSlots[nationSlot] = emptyName;
    }
    nationStatusTags[nationSlot] = kSessionTagDead; // 'dead'
  } else {
    bool wrapInParens;
    if (g_apNationStates[nationSlot]->diplomacyEligibility == 0 ||
        !g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot))) {
      wrapInParens = true;
    } else {
      wrapInParens = false;
    }
    CString nationName;
    g_apNationStates[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
    const char* prefix = g_szUiOpenParen;
    if (!wrapInParens) {
      prefix = g_szEmptyString;
    }
    CString prefixText(prefix);
    defaultNationTextSlots[nationSlot] = prefixText;
    defaultNationTextSlots[nationSlot] += nationName;
    const char* suffix = g_szUiCloseParen;
    if (!wrapInParens) {
      suffix = g_szEmptyString;
    }
    defaultNationTextSlots[nationSlot] += suffix;
    nationDisplayNameSlots[nationSlot] = defaultNationTextSlots[nationSlot];
    if (!g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot))) {
      nationStatusTags[nationSlot] = kSessionTagDeca; // 'deca'
    }
  }
}

// FUNCTION: IMPERIALISM 0x0054cde0
void TMultiplayerMgr::CreateAndQueueTurnEventPacketTagPOGC() {
  TCancelGameOptionsCommand* command = new TCancelGameOptionsCommand();
  command->ICommand(kSessionTagCgop, g_pAmbitApplication, 0, 0, 0); // 'pogc'
  g_pAmbitApplication->DispatchUiSelectionToHandler(command);
}

// FUNCTION: IMPERIALISM 0x0054ce80
void TMultiplayerMgr::SendCityStateMessage(int nationSlot, int destinationSlot) {
  TurnEvent2CPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.fromNetworkId = 0;
  packet.messageLength = 0x18c;
  packet.eventCode = 0x2c;
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  if (destinationSlot == -2 || destinationSlot == -3) {
    packet.toNetworkId = 0;
  } else if (destinationSlot == -1) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[destinationSlot];
  }
  packet.nationSlot = static_cast<short>(nationSlot);
  TGreatPower* nation = g_apNationStates[nationSlot];
  packet.specialResourceTradeBalance = nation->specialResourceTradeBalance;
  packet.aidAllocationTotal = nation->aidAllocationTotal;
  TCity* city;
  if (nation == 0) {
    city = 0;
  } else {
    city = nation->city;
  }
  if (city != 0) {
    for (int i = 0; i < kMilitaryUnitKindCount; ++i) {
      packet.militaryRecruitCountByKind[i] = city->militaryRecruitCountByKind[i];
    }
    for (int j = 0; j < kCivilianUnitKindCount; ++j) {
      packet.civilianRecruitCountByKind[j] = city->civilianRecruitCountByKind[j];
    }
    for (int industryActionSlot = 0; industryActionSlot < kIndustryActionSlotCount;
         ++industryActionSlot) {
      packet.orderCountByType[industryActionSlot] = city->orderCountByType[industryActionSlot];
    }
    packet.cityRollingItemProductionScore = city->rollingItemProductionScore;
    packet.cityFieldB4 = city->powerAvailable;
    short* stock = city->stockByType;
    for (int stockType = 0; stockType < kResourceKindCount; ++stockType) {
      packet.cityStock[stockType] = stock[stockType];
    }
    for (int slot = 0; slot < 0x10; ++slot) {
      packet.productionOrderTable[slot] = city->productionOrderTable[slot];
    }
    for (int slot2 = 0; slot2 < 0x10; ++slot2) {
      packet.productionAccum[slot2] = city->productionAccum[slot2];
    }
    packet.populationGrowthPenaltyTicks = city->populationGrowthPenaltyTicks;
    for (int record = 0; record < 0x17; ++record) {
      TProductionOrder* order = city->orderSlots[record];
      if (order == 0) {
        packet.orderAccumulatedValues[record] = 0;
      } else {
        packet.orderAccumulatedValues[record] = order->accumulatedValue;
      }
    }
    TPopulationMgr* summary = city->productionSummary;
    packet.popFieldAt8 = summary->populationCount;
    packet.popFieldAtC = summary->populationCountFloat;
    packet.popStockLevel = summary->strength;
    packet.popExtraAt1e = summary->extraAt1e;
    packet.popFieldAt20 = summary->fieldAt20;
    packet.popBucketWords[0] = summary->baselineSlots->lowSkillCount;
    packet.popBucketWords[1] = summary->baselineSlots->mediumSkillCount;
    packet.popBucketWords[2] = summary->baselineSlots->highSkillCount;
    packet.popBucketWords[3] = summary->productionSlots->lowSkillCount;
    packet.popBucketWords[4] = summary->productionSlots->mediumSkillCount;
    packet.popBucketWords[5] = summary->productionSlots->highSkillCount;
    packet.popBucketWords[6] = summary->pendingDeltaSlots->lowSkillCount;
    packet.popBucketWords[7] = summary->pendingDeltaSlots->mediumSkillCount;
    packet.popBucketWords[8] = summary->pendingDeltaSlots->highSkillCount;
    g_pNetMgr->Send(&packet, destinationSlot == -3);
  }
}

// FUNCTION: IMPERIALISM 0x0054d1f0
void TMultiplayerMgr::SendNationStateMessage(short nationSlot, int destinationSlot) {
  TurnEvent19Packet packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.eventCode = 0x19;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.toNetworkId = -1;
  packet.messageLength = 0;
  packet.messageLength = 0x118;
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  if (destinationSlot == -2 || destinationSlot == -3) {
    packet.toNetworkId = 0;
  } else if (destinationSlot == -1) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[destinationSlot];
  }
  TGreatPower* nation = g_apNationStates[nationSlot];
  packet.nationSlot = nationSlot;
  SendBankStatement(true, nationSlot);
  packet.transportCapacity = nation->transportCapacity;
  for (int industryActionSlot = 0; industryActionSlot < kIndustryActionSlotCount;
       ++industryActionSlot) {
    packet.orderCountByType[industryActionSlot] =
        nation->city->orderCountByType[industryActionSlot];
  }
  for (int i = 0; i < 0x17; ++i) {
    packet.externalStateByTarget[i] = nation->GetStockpile(static_cast<short>(i));
  }
  for (int metricSlot = 0; metricSlot < 0x11; ++metricSlot) {
    packet.metricBySlot7C[metricSlot] = nation->GetTradeOffersFor(static_cast<short>(metricSlot));
  }
  for (short target = 0; target < 0x17; ++target) {
    packet.diplomacyPolicyByNation[target] = nation->diplomacyPolicyByNation[target];
    packet.diplomacyGrantByNation[target] = nation->diplomacyGrantByNation[target];
    packet.tradePolicyByNation[target] = nation->tradePolicyByNation[target];
  }
  g_pNetMgr->Send(&packet, destinationSlot == -3);
}

// FUNCTION: IMPERIALISM 0x0054d3d0
void TMultiplayerMgr::SendMinorStateMessage(short nationSlot, int destinationSlot) {
  TurnEvent2DMinorNeedPacket packet;
  packet.messageTag = kControlTagTime;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetPlayerCountry());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = -1;
  packet.messageLength = 0;
  packet.messageLength = 0x4c;
  packet.eventCode = 0x2d;
  packet.syncPhase = static_cast<GamePhaseStorage>(g_pGameFlowState->syncPhase);
  if (destinationSlot == -2 || destinationSlot == -3) {
    packet.toNetworkId = 0;
  } else if (destinationSlot == -1) {
    packet.toNetworkId = -1;
  } else {
    packet.toNetworkId = g_pGameFlowState->nationSessionIds[destinationSlot];
  }
  packet.nationSlot = nationSlot;
  TMinor* nation = g_apSecondaryNationStateSlots[nationSlot];
  for (short targetNation = 0; targetNation < kNationSlotCount; ++targetNation) {
    packet.tradePolicyByNation[targetNation] = nation->tradePolicyByNation[targetNation];
  }
  g_pNetMgr->Send(&packet, destinationSlot == -3);
}

// FUNCTION: IMPERIALISM 0x0054d4e0
bool TMultiplayerMgr::AttemptSave(int mode, char* label, bool showFailureDialog) {
  bool allReachable = g_pNetMgr->Ping() == 0;
  if (allReachable) {
    SaveGameWithModeAndOptionalLabel(mode, label);
  }
  if (showFailureDialog && !allReachable) {
    CString message;
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2742, 0x28);
    g_pViewMgr->PostModalMessage(&message, 0);
  }
  return allReachable;
}

// FUNCTION: IMPERIALISM 0x005e34b0
bool ReturnTrueRuntimeCredentialInitStub() {
  return true;
}

// Turn-resume pass: the host drops absent nations from the pending mask and broadcasts it,
// clients acknowledge the pending event, then both mark the local nation ready.
