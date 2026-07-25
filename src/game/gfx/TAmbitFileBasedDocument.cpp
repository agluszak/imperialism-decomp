#include "game/gfx/TAmbitFileBasedDocument.h"
#include "game/ui_tags_widgets.h"

#include "game/GameAssert.h"
#include "game/app/TAnimator.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/military/TArmyMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/core/TFileStream.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x0049e5a0
// TAmbitFileBasedDocument::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049e5d0
// TAmbitFileBasedDocument::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAmbitFileBasedDocument, TFileBasedDocument)

// FUNCTION: IMPERIALISM 0x0049e5f0
TAmbitFileBasedDocument::TAmbitFileBasedDocument() {}

// SYNTHETIC: IMPERIALISM 0x0049e610
// TAmbitFileBasedDocument::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049e640
TAmbitFileBasedDocument::~TAmbitFileBasedDocument() {}

// FUNCTION: IMPERIALISM 0x0049e660
void TAmbitFileBasedDocument::IAmbitDocument(ArchiveStreamAdapter*, unsigned long) {}

// FUNCTION: IMPERIALISM 0x0049e680
void TAmbitFileBasedDocument::DoMakeViews(unsigned char) {}

// FUNCTION: IMPERIALISM 0x0049e6a0
void TAmbitFileBasedDocument::DoRead(ArchiveStreamAdapter* file, unsigned char flags) {
  (void)flags;

  TFileStream* stream = new TFileStream();
  stream->SetBackingArchive(file);

  int fileMagic;
  int savedSessionSlot;
  stream->ReadBytes(&fileMagic, 4);
  stream->ReadBytes(&g_nSaveFormatVersion, 4);
  stream->ReadBytes(&savedSessionSlot, 4);
  stream->ReadBytes(g_ScenarioSaveNameBuffer_006A2178, 0x20);

  bool invalidSaveFile = false;
  if (fileMagic != kControlTagAMBI) {
    CString message;
    g_pSimMgr->GetString(0x2737, 7, &message);
    g_pUiRuntimeContext->ModalMessage(message, g_ptSaveLoadErrorModalMessage, 2, 0);
    invalidSaveFile = true;
  } else if (g_nSaveFormatVersion < 0x23) {
    CString message;
    g_pSimMgr->GetString(0x2737, 8, &message);
    g_pUiRuntimeContext->ModalMessage(message, g_ptSaveLoadErrorModalMessage, 2, 0);
    invalidSaveFile = true;
  }

  if (!invalidSaveFile && g_pSimMgr->multiplayerSessionRole == 2 &&
      savedSessionSlot != g_pGameFlowState->queueSyncDword) {
    CString message;
    g_pSimMgr->GetString(0x2737, 7, &message);
    g_pUiRuntimeContext->ModalMessage(message, g_ptSaveLoadErrorModalMessage, 2, 0);
    invalidSaveFile = true;
  }

  if (!invalidSaveFile) {
    unsigned char* discardedMapMetadata = new unsigned char[0x1950];
    if (discardedMapMetadata == 0) {
      GAME_FAIL_NIL_POINTER();
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szUAmbitSourcePath, 0x482);
    }
    stream->ReadBytes(discardedMapMetadata, 0x1950);
    stream->ReadBytes(discardedMapMetadata, 0x24);
    delete[] discardedMapMetadata;

    g_pGlobalUiRootController->ReadFrom(stream);
    g_pSimMgr->ReadFrom(stream);
    g_pUiAnimator->ReadFrom(stream);
    g_pNationInteractionStateManager->ReadFrom(stream);
    g_pDiplomacyTurnStateManager->ReadFrom(stream);
    g_pCityOrderCapabilityState->ReadFrom(stream);
    g_pGlobalMapState->ReadFrom(stream);
    g_pActiveMapOrderContext->ReadFrom(stream);
    g_pNavyOrderManager->ReadFrom(stream);
    g_pMapContextActionManager->ReadFrom(stream);
    for (short descriptorIndex = 0; descriptorIndex < kTerrainTypeDescriptorTableCount;
         ++descriptorIndex) {
      if (g_apTerrainTypeDescriptorTable[descriptorIndex] != 0) {
        g_apTerrainTypeDescriptorTable[descriptorIndex]->ReadFrom(stream);
      }
    }
    g_pUiRuntimeContext->ReadFrom(stream);
    g_pStrategicMapViewSystem->ReadFrom(stream);
    g_pNewsMgr->ReadFrom(stream);
    g_pHelpMgr->ReadFrom(stream);
  }

  stream->Free();

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0 &&
        !g_apNationStates[nationSlot]->IsRemote()) {
      g_apNationStates[nationSlot]->BuildTransportLinkedInfluenceMap(0);
    }
  }
  g_nSaveFormatVersion = -1;
}

// FUNCTION: IMPERIALISM 0x0049eb30
void TAmbitFileBasedDocument::DoWrite(ArchiveStreamAdapter* file, unsigned char flags) {
  (void)flags;

  TFileStream* stream = new TFileStream();
  stream->SetBackingArchive(file);

  stream->WriteBytes(const_cast<int*>(&g_nAmbitSaveFileMagic), 4);
  stream->WriteBytes(const_cast<int*>(&g_nCurrentAmbitSaveFormatVersion), 4);
  int savedSessionSlot = g_pGameFlowState->queueSyncDword;
  stream->WriteBytes(&savedSessionSlot, 4);
  stream->WriteBytes(g_ScenarioSaveNameBuffer_006A2178, 0x20);

  char* tileOwnerTags = new char[0x1950];
  if (tileOwnerTags == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szUAmbitSourcePath, 0x4e7);
  }
  char* nextTileOwnerTag = tileOwnerTags;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    *nextTileOwnerTag++ = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04;
  }
  stream->WriteBytes(tileOwnerTags, 0x1950);
  delete[] tileOwnerTags;

  int economicQuarter = g_pSimMgr->economicTurn / 4;
  stream->WriteBytes(&economicQuarter, 2);
  unsigned char difficultyLevel = static_cast<unsigned char>(g_pSimMgr->difficultyLevel);
  stream->WriteBytes(&difficultyLevel, 1);
  unsigned char activeNationSlot = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  stream->WriteBytes(&activeNationSlot, 1);

  CString activeNationName;
  g_apTerrainTypeDescriptorTable[static_cast<signed char>(activeNationSlot)]
      ->FormatOverlayTerrainLabelText(&activeNationName);
  char* activeNationNameBuffer = activeNationName.GetBuffer(0x21);
  stream->WriteBytes(activeNationNameBuffer, 0x20);
  activeNationName.ReleaseBuffer(-1);

  g_pGlobalUiRootController->WriteTo(stream);
  g_pSimMgr->WriteTo(stream);
  g_pUiAnimator->WriteTo(stream);
  g_pNationInteractionStateManager->WriteTo(stream);
  g_pDiplomacyTurnStateManager->WriteTo(stream);
  g_pCityOrderCapabilityState->WriteTo(stream);
  g_pGlobalMapState->WriteTo(stream);
  g_pActiveMapOrderContext->WriteTo(stream);
  g_pNavyOrderManager->WriteTo(stream);
  g_pMapContextActionManager->WriteTo(stream);
  TCountry** terrainDescriptor = g_apTerrainTypeDescriptorTable;
  int descriptorsRemaining = kTerrainTypeDescriptorTableCount;
  while (descriptorsRemaining != 0) {
    if (*terrainDescriptor != 0) {
      (*terrainDescriptor)->WriteTo(stream);
    }
    ++terrainDescriptor;
    --descriptorsRemaining;
  }
  g_pUiRuntimeContext->WriteTo(stream);
  g_pStrategicMapViewSystem->WriteTo(stream);
  g_pNewsMgr->WriteTo(stream);
  g_pHelpMgr->WriteTo(stream);

  stream->Free();
}

// FUNCTION: IMPERIALISM 0x0049ee70
void TAmbitFileBasedDocument::SaveDocument(long saveMode) {
  (void)saveMode;
  if (g_saveDocumentAssertGuard == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szUAmbitSourcePath, 0x537);
  }
}
