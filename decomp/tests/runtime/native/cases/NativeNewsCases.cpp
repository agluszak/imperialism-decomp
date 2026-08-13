#include "NativeTransition.h"
#include "JsonArray.h"
#include "JsonObject.h"

#include "game/assets/TAssetMgr.h"
#include "game/globals/assets_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_screens/TNewsMgr.h"

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
