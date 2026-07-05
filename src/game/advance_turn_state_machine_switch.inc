  case 4:
    turnStateCode = 5;
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    if (redrawEnabled != 0) {
      if (activeNationSlot == -1 ||
          g_apTerrainTypeDescriptorTable[activeNationSlot] == nullptr ||
          (activeNationSlot <= 6 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot >= 100 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot <= 199)) {
        PostMainWindowCommand100ForTurnFlow();
      }
    }
    break;

  case 5: {
    const char alertsPending = ShowTurnAlertsForActiveNation();
    turnFlowStatusFlags = alertsPending;
    if (alertsPending != 0) {
      break;
    }
    turnStateCode = 6;
    if (redrawEnabled != 0) {
      ConfigureTurnResumeStateAndNationMask();
      turnStateCode = 0x13;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 6: {
    turnStateCode = 7;
    if (redrawEnabled != 0) {
      ConfigureTurnResumeStateAndNationMask();
    }
    if (redrawEnabled != 1 && g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    }
    if (redrawEnabled == 0) {
      TGreatPower** nationCursor = g_apNationStates;
      TGreatPower** nationEnd = reinterpret_cast<TGreatPower**>(&g_apNationStates_End);
      while (nationCursor < nationEnd) {
        TGreatPower* nation = *nationCursor;
        if (nation != nullptr && nation->diplomacyEligibilityA0 != 0 &&
            GetNationTrackedOrderCount(nation) > 0) {
          SetOutputDevice();
          DispatchUiSlot4C();
          break;
        }
        ++nationCursor;
      }
    } else if (IsNationTerrainEligible(activeNationSlot)) {
      DispatchUiSlot4C();
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->ProcessPendingDiplomacyProposalQueue();
      }
    }
    if (ShouldDispatchNextTradePacket(this)) {
      // 0x57df05: new TNextDiplomationCommand() + immediate dispatch; the original
      // calls the method even when operator new returned null (kept faithfully).
      TNextDiplomationCommand* nextCommand = new TNextDiplomationCommand();
      nextCommand->DispatchUiPacketWithTagNEXT();
    }
    break;
  }

  case 7: {
    turnStateCode = 9;
    if (g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    }
    if (redrawEnabled != 0) {
      ConfigureTurnResumeStateAndNationMask();
      SetOutputDevice();
      DispatchUiSlot4C();
      if (g_pUiRuntimeContext != nullptr) {
        g_pUiRuntimeContext->DispatchDecisionSlot98(-1, 0, 0, 0x16);
      }
    }
    if (redrawEnabled != 2) {
      DispatchTurnEvent2134AndRefreshNationPanels();
    }
    break;
  }

  case 8: {
    turnStateCode = 0xb;
    RefreshMapSystemsAndPrepareOrderExecution();
    if (redrawEnabled != 0) {
      ConfigureTurnResumeStateAndNationMask();
      turnStateCode = 0x13;
      PostMainWindowCommand100ForTurnFlow();
      break;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 9: {
    turnStateCode = 10;
    if (redrawEnabled != 2) {
      DispatchEligibleNationTurnCallback158();
      PostMainWindowCommand100ForTurnFlow();
      break;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 10: {
    turnStateCode = 0x14;
    if (g_pSimMgr != nullptr) {
      g_pSimMgr->RebuildPrimaryNationStateForSlot(0, 0);
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 0xb: {
    char actionNeeded = 0;
    for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr) {
        continue;
      }
      if (QueryJoinEmpireModePendingForNationAf(nation) == 0) {
        continue;
      }
      TGreatPower* activeNation = g_apNationStates[activeNationSlot];
      if (activeNation != nullptr) {
        activeNation->ApplyJoinEmpireMode1TargetTransition(nationSlot);
        actionNeeded = 1;
      }
    }
    if (actionNeeded == 0) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0xc: {
    turnStateCode = 0xe;
    if (IsNationTerrainEligible(activeNationSlot)) {
      DispatchUiSlot4C();
      SetOutputDevice();
      break;
    }
    if (!IsNationTerrainEligible(activeNationSlot)) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0xd: {
    turnStateCode = 0x19;
    if (GetByteFlagAtOffset8() != 0 && IsNationTerrainEligible(activeNationSlot)) {
      DispatchUiSlot4C();
      break;
    }
    if (!IsNationTerrainEligible(activeNationSlot)) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0xe: {
    turnStateCode = 0x10;
    if (g_pDiplomacyTurnStateManager != nullptr &&
        g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e != -1) {
      const short lastProcessed = g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e;
      turnStateCode = static_cast<int>(lastProcessed != activeNationSlot) + 0x16;
    }
    RunQuarterGateCheckAndMaybeRequeue(this);
    break;
  }

  case 0xf: {
    turnStateCode = 0x12;
    if (g_pUiViewManager != nullptr) {
      // TODO: port TAssetMgr/TViewMgr slot used at 0x005df3f0.
    }
    RebuildNationRankingDataAndUiCache();
    DispatchUiSlot4C();
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (!IsNationTerrainEligible(nationSlot)) {
        continue;
      }
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->ExecuteNationPendingActionStateMachine();
      }
    }
    if (g_nTurnCooldownDeferCounter006A43C4 < 1) {
      g_nTurnCooldownDeferCounter006A43C4 = 0;
      g_nTurnCooldownSideFlag00698B10 = 1;
      HandleTurnEndSavePaths(this);
    } else {
      const int phaseFlags = IsTurnFlowPhaseOutsideRange4To5();
      if ((phaseFlags & 0xf) == 10) {
        HandleTurnEndSavePaths(this);
      }
    }
    if (redrawEnabled != 0) {
      if (!IsNationTerrainEligible(activeNationSlot)) {
        PostMainWindowCommand100ForTurnFlow();
      }
    }
    break;
  }

  case 0x10: {
    turnStateCode = 0x11;
    turnFlowStatusFlags = 0;
    runtimeSubsystemIndex = 0;
    SetGlobalTurnStateCodeIfAllowed(0);
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 0x11: {
    turnStateCode = 0xf;
    char actionNeeded = 1;
    const short capabilityBefore = ReadCityOrderCapabilityField262();
    UpdateCityOrderCapabilityUnlockProgress();
    if (capabilityBefore == ReadCityOrderCapabilityField262()) {
      runtimeSubsystemIndex |= 0x40;
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (g_pSimMgr != nullptr && g_pSimMgr->activeNationSlot == nationSlot &&
          g_nTurnCooldownDeferCounter006A43C4 < 1) {
        g_nTurnCooldownDeferCounter006A43C4 = 0;
        g_nTurnCooldownSideFlag00698B10 = 1;
        if (!IsNationTerrainEligible(activeNationSlot)) {
          short unlockSlot = ConsumeFirstPendingAbilityUnlock();
          if (unlockSlot != -1) {
            DispatchUiSlot4C();
            actionNeeded = 0;
          }
          continue;
        }
      }
      short unlockSlot = ConsumeFirstPendingAbilityUnlock();
      while (unlockSlot != -1) {
        unlockSlot = ConsumeFirstPendingAbilityUnlock();
      }
    }
    if (actionNeeded != 0) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0x12: {
    turnStateCode = 5;
    if (g_pUiViewManager != nullptr) {
      // TODO: port TAssetMgr/TViewMgr slot used at 0x005df3f0.
    }
    if (g_pGlobalMapState != nullptr) {
      g_pGlobalMapState->DispatchTurnEvent7DDForActiveNation();
    }
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->RefreshViewSlot48();
    }
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr || nationSlot == -1) {
        continue;
      }
      if (!IsNationTerrainEligible(nationSlot)) {
        continue;
      }
      nation->IsEncodedNationSlotMinus200Equal(0);
      nation->DispatchMissionNodeCallbacksAndClearQueue();
    }
    ResetDualAudioCuePools();
    PushCueToDualAudioCuePools();
    PushCueToDualAudioCuePools();
    SelectAndScheduleRandomAudioCue();
    if (!IsNationTerrainEligible(activeNationSlot)) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0x13: {
    TMultiplayerMgr* gameFlow = reinterpret_cast<TMultiplayerMgr*>(g_pGameFlowState);
    if (gameFlow != nullptr) {
      turnStateCode = gameFlow->activeNationSlotIndex;
    }
    HandleTurnResumeStateTelemetry();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(activeNationSlot, 0x5e4);
    }
    break;
  }

  case 0x14: {
    turnStateCode = 0x15;
    if (g_pMapContextActionManager != nullptr) {
      // TODO: port map-context slot at 0x004a1e40.
    }
    if (redrawEnabled != 0) {
      ConfigureTurnResumeStateAndNationMask();
      turnStateCode = 0x13;
    }
    break;
  }

  case 0x15: {
    turnStateCode = 0xd;
    RefreshNavyOrderCycleAndClearReadyFlags();
    if (redrawEnabled != 2) {
      RecomputeTileStrategicScoreHeatmap();
      RecomputeNationOrderPriorityMetrics();
      for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
        if (nationSlot == -1 || g_apTerrainTypeDescriptorTable[nationSlot] == nullptr) {
          continue;
        }
        if (nationSlot < 7 && IsNationProfileInMinorRange100To199() != 0) {
          continue;
        }
        TGreatPower* nation = g_apNationStates[nationSlot];
        if (nation != nullptr) {
          // TODO: port TGreatPower slot at 0x004d8920 (turn-prep per nation).
        }
      }
    }
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (!IsNationTerrainEligible(nationSlot)) {
        continue;
      }
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->SetNationTransferTargetCodeAndNotifyEligiblePeers(0);
      }
    }
    const short tickA = GetTurnTickSlot3C();
    const short tickB = GetTurnTickSlot3C();
    if (((tickB % 0x28) == 0) && (phaseFlags[tickA / 0x28] != 0) && redrawEnabled != 2 &&
        g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->SelectPriorityNationIndicesForMinorCapabilityRows();
    }
    if (redrawEnabled != 0) {
      ConfigureTurnResumeStateAndNationMask();
      turnStateCode = 0x13;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 0x17:
    DispatchUiSlot4C();
    break;

  case 0x19: {
    turnStateCode = 8;
    char actionNeeded = 0;
    if (g_pSimMgr != nullptr) {
      const short localizationNation = g_pSimMgr->activeNationSlot;
      TGreatPower* localizationNationState = g_apNationStates[localizationNation];
      if (localizationNationState != nullptr) {
        const short encoded = localizationNationState->encodedNationSlot;
        if (encoded > 99 && encoded < 200) {
          TGreatPower* activeNation = g_apNationStates[activeNationSlot];
          if (activeNation != nullptr) {
            activeNation->ApplyJoinEmpireMode1TargetTransition(localizationNation);
            actionNeeded = 1;
          }
        }
      }
    }
    for (int removeNationSlot = 0; removeNationSlot < 7; ++removeNationSlot) {
      if (g_apTerrainTypeDescriptorTable[removeNationSlot] == nullptr ||
          g_apNationStates[removeNationSlot] == nullptr) {
        continue;
      }
      if (QueryNationAdvisorSlot90Predicate28(g_apNationStates[removeNationSlot]) == 0) {
        RemoveNationSlotAndNotifyPeers();
      }
    }
    for (int secondaryIndex = 7; secondaryIndex < 36; ++secondaryIndex) {
      TMinor* secondaryNation = g_apSecondaryNationStateSlots[secondaryIndex];
      if (secondaryNation != nullptr &&
          QueryNationAdvisorSlot90Predicate28(reinterpret_cast<TGreatPower*>(secondaryNation)) ==
              0) {
        for (short percentNationSlot = 0; percentNationSlot < 7; ++percentNationSlot) {
          if (!IsNationTerrainEligible(percentNationSlot)) {
            continue;
          }
          TGreatPower* nation = g_apNationStates[percentNationSlot];
          if (nation != nullptr) {
            nation->SetNationPercentFieldByModeAndDescriptorLinks(0, 100);
          }
        }
      }
    }
    if (actionNeeded != 0) {
      break;
    }
    int eligibleMinorCount = 0;
    for (int countNationSlot = 0; countNationSlot < 7; ++countNationSlot) {
      if (IsNationTerrainEligible(static_cast<short>(countNationSlot))) {
        ++eligibleMinorCount;
      }
    }
    if (eligibleMinorCount == 1 && IsNationTerrainEligible(activeNationSlot)) {
      actionNeeded = 1;
      UpdatePersistentTopTenNationScores();
      DispatchUiSlot4C();
    }
    if (actionNeeded == 0) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0x16:
    UpdatePersistentTopTenNationScores();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  case 100:
    turnStateCode = 4;
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  // Jump-table ground truth (0x57dad8, index-byte table 0x57ebec): case 0x71 -> 0x57eabf
  // (posts 0x104f), case 0x72 -> 0x57ead8 (posts 0x5e4). The old merged port dropped both
  // event codes.
  case 0x71:
    turnStateCode = 4;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x104f);
    break;

  case 0x72:
    turnStateCode = 4;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e4);
    break;

  case 0x68:
    turnStateCode = 4;
    SyncNationField790FromLocalizationStateId();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  case 0x6b:
  case 0x65:
  case 0x66:
  case 0x67:
  case 0x69:
  case 0x6a:
  case 0x6c:
  case 0x6d:
  case 0x6e:
  case 0x6f:
  case 0x70:
    turnStateCode = 4;
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;
