#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"

#include "game/assets/TAssetMgr.h"
#include "game/globals/assets_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TSimMgr.h"

#include <stdio.h>
#include <string.h>

namespace {

const int kNewsTemplateCount = 360;
const int kNewsRowBytes = 24;
const int kNewsTableBytes = kNewsTemplateCount * kNewsRowBytes;

unsigned int ByteSwapNewsDword(unsigned int value) {
  return ((value & 0x000000ffU) << 24) | ((value & 0x0000ff00U) << 8) |
         ((value & 0x00ff0000U) >> 8) | ((value & 0xff000000U) >> 24);
}

void WriteSyntheticNewsTab(int eventStoryId) {
  FILE* file = fopen("news.tab", "wb");
  if (file == 0) {
    return;
  }
  for (int index = 0; index < kNewsTemplateCount; ++index) {
    unsigned int id = index == 0 ? static_cast<unsigned int>(eventStoryId) : 1U;
    unsigned int be = ByteSwapNewsDword(id);
    fwrite(&be, 4, 1, file);
    unsigned int zero = 0;
    fwrite(&zero, 4, 1, file);
    fwrite(&zero, 4, 1, file);
    fwrite(&zero, 4, 1, file);
    fwrite(&zero, 4, 1, file);
    fwrite(&zero, 4, 1, file);
  }
  fclose(file);
}

RuntimeActionResult LoadNewsStoryIds(JsonArray* ids) {
  if (g_pAssetMgr == 0 || g_pLanguageMgr == 0) {
    return RuntimeActionResult::Failure("news table assets are unavailable");
  }

  CFile* stream = g_pAssetMgr->LoadTableResourceStreamByName(g_pLanguageMgr->GetNewsTabPath());
  int byteCount = stream != 0 ? g_pAssetMgr->GetResourceStreamSize(stream) : 0;
  if (stream == 0 || byteCount != kNewsTableBytes) {
    g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);
    WriteSyntheticNewsTab(-1003);
    stream = g_pAssetMgr->LoadTableResourceStreamByName(g_pLanguageMgr->GetNewsTabPath());
    byteCount = stream != 0 ? g_pAssetMgr->GetResourceStreamSize(stream) : 0;
  }
  if (stream == 0 || byteCount != kNewsTableBytes) {
    g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);
    return RuntimeActionResult::Failure("NEWS.TAB does not contain 360 rows");
  }

  unsigned char* buffer = new unsigned char[kNewsTableBytes];
  int readCount = kNewsTableBytes;
  g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, buffer, &readCount);
  g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);
  if (readCount != kNewsTableBytes) {
    delete[] buffer;
    return RuntimeActionResult::Failure("NEWS.TAB read was incomplete");
  }
  for (int index = 0; index < kNewsTemplateCount; ++index) {
    unsigned int raw = 0;
    memcpy(&raw, buffer + index * kNewsRowBytes, 4);
    ids->Add(static_cast<int>(ByteSwapNewsDword(raw)));
  }
  delete[] buffer;
  return RuntimeActionResult::Success();
}

RuntimeActionResult RunNewspaperConstruction(NativeTransition& transition, bool queueMiscEvent) {
  if (g_pNewsMgr == 0 || g_pNewsMgr->sharedEventRecordQueue == 0) {
    return RuntimeActionResult::Failure("newspaper state is unavailable");
  }

  JsonArray storyIds;
  RuntimeActionResult loaded = LoadNewsStoryIds(&storyIds);
  if (!loaded.Succeeded()) {
    return loaded;
  }

  g_pNewsMgr->sharedEventRecordQueue->InvokePtrListResetHook();
  if (queueMiscEvent) {
    g_pNewsMgr->AddMiscEvent(999, 3, 1);
  }

  JsonObject operation;
  operation.Set("story_ids", storyIds.Release());
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pNewsMgr->StartNewsPhase();
  return transition.Finish();
}

} // namespace

RuntimeActionResult RunConstructNewspaperPage(NativeTransition& transition) {
  return RunNewspaperConstruction(transition, false);
}

RuntimeActionResult RunConstructNewspaperPageMiscEvent(NativeTransition& transition) {
  return RunNewspaperConstruction(transition, true);
}

RuntimeActionResult RunNewspaperTurnStop(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }

  JsonArray storyIds;
  RuntimeActionResult loaded = LoadNewsStoryIds(&storyIds);
  if (!loaded.Succeeded()) {
    return loaded;
  }
  g_pSimMgr->turnStateCode = 0xf;

  JsonObject operation;
  operation.Set("story_ids", storyIds.Release());
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  return transition.Finish(json_value_init_string("newspaper"));
}

RuntimeActionResult RunSecondTurnSequence(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pTechMgr == 0) {
    return RuntimeActionResult::Failure("turn sequence state is unavailable");
  }

  JsonArray storyIds;
  RuntimeActionResult loaded = LoadNewsStoryIds(&storyIds);
  if (!loaded.Succeeded()) {
    return loaded;
  }

  g_pSimMgr->economicTurn = 2;
  g_pSimMgr->turnStateCode = 5;
  g_pSimMgr->preferenceValues[8] = 0;
  for (int techId = 3; techId < 0x1d; ++techId) {
    g_pTechMgr->perTechUnlockFlag180[techId] = 0;
    g_pTechMgr->prioritySlots04[techId] = 0;
  }

  JsonObject operation;
  operation.Set("story_ids", storyIds.Release());
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  int stepCount = 0;
  while (g_pSimMgr->turnStateCode != 0xe && stepCount < 32) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    ++stepCount;
  }
  if (g_pSimMgr->turnStateCode != 0xe) {
    return RuntimeActionResult::Failure("turn sequence did not reach the Deal Book");
  }

  JsonArray stops;
  JsonArray rngStates;
  stops.Add("deal_book");
  rngStates.Add(RuntimeCrtRandStateForTests());
  while (g_pSimMgr->turnStateCode != 0x12 && stepCount < 48) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    ++stepCount;
  }
  if (g_pSimMgr->turnStateCode != 0x12) {
    return RuntimeActionResult::Failure("turn sequence did not reach the newspaper");
  }
  stops.Add("newspaper");
  rngStates.Add(RuntimeCrtRandStateForTests());

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("turn sequence did not return to player orders");
  }
  stops.Add("player_orders");
  rngStates.Add(RuntimeCrtRandStateForTests());

  JsonObject result;
  result.Set("stops", stops.Release());
  result.Set("rng_states", rngStates.Release());
  result.Set("economic_turn", g_pSimMgr->economicTurn);
  return transition.Finish(result.Release());
}

RuntimeActionResult RunConsecutiveTurnSequence(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pTechMgr == 0) {
    return RuntimeActionResult::Failure("turn sequence state is unavailable");
  }

  JsonArray storyIds;
  RuntimeActionResult loaded = LoadNewsStoryIds(&storyIds);
  if (!loaded.Succeeded()) {
    return loaded;
  }

  g_pSimMgr->economicTurn = 2;
  g_pSimMgr->turnStateCode = 5;
  g_pSimMgr->preferenceValues[8] = 0;
  for (int techId = 3; techId < 0x1d; ++techId) {
    g_pTechMgr->perTechUnlockFlag180[techId] = 0;
    g_pTechMgr->prioritySlots04[techId] = 0;
  }

  JsonObject operation;
  operation.Set("story_ids", storyIds.Release());
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  JsonArray stops;
  JsonArray rngStates;
  JsonArray economicTurns;
  for (int turn = 0; turn < 5; ++turn) {
    int stepCount = 0;
    while (g_pSimMgr->turnStateCode != 0xe && stepCount < 32) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      ++stepCount;
    }
    if (g_pSimMgr->turnStateCode != 0xe) {
      return RuntimeActionResult::Failure("turn sequence did not reach the Deal Book");
    }
    stops.Add("deal_book");
    rngStates.Add(RuntimeCrtRandStateForTests());

    while (g_pSimMgr->turnStateCode != 0x12 && stepCount < 48) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      ++stepCount;
    }
    if (g_pSimMgr->turnStateCode != 0x12) {
      return RuntimeActionResult::Failure("turn sequence did not reach the newspaper");
    }
    stops.Add("newspaper");
    rngStates.Add(RuntimeCrtRandStateForTests());

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("turn sequence did not return to player orders");
    }
    stops.Add("player_orders");
    rngStates.Add(RuntimeCrtRandStateForTests());
    economicTurns.Add(g_pSimMgr->economicTurn);
  }

  JsonObject result;
  result.Set("stops", stops.Release());
  result.Set("rng_states", rngStates.Release());
  result.Set("economic_turns", economicTurns.Release());
  return transition.Finish(result.Release());
}
