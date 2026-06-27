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

  case 6:
    AdvanceGlobalTurnStateMachineCase6(this);
    break;
  case 7:
    AdvanceGlobalTurnStateMachineCase7(this);
    break;
  case 8:
    AdvanceGlobalTurnStateMachineCase8(this);
    break;
  case 9:
    AdvanceGlobalTurnStateMachineCase9(this);
    break;
  case 10: {
    AdvanceGlobalTurnStateMachineCase10(this);
    break;
  }
  case 0xb:
    AdvanceGlobalTurnStateMachineCaseB(this);
    break;
  case 0xc:
    AdvanceGlobalTurnStateMachineCaseC(this);
    break;
  case 0xd:
    AdvanceGlobalTurnStateMachineCaseD(this);
    break;
  case 0xe:
    AdvanceGlobalTurnStateMachineCaseE(this);
    break;
  case 0xf:
    AdvanceGlobalTurnStateMachineCaseF(this);
    break;
  case 0x10: {
    AdvanceGlobalTurnStateMachineCase10State(this);
    break;
  }
  case 0x11:
    AdvanceGlobalTurnStateMachineCase11(this);
    break;
  case 0x12:
    AdvanceGlobalTurnStateMachineCase12(this);
    break;
  case 0x13:
    AdvanceGlobalTurnStateMachineCase13(this);
    break;
  case 0x14:
    AdvanceGlobalTurnStateMachineCase14(this);
    break;
  case 0x15:
    AdvanceGlobalTurnStateMachineCase15(this);
    break;
  case 0x17:
    AdvanceGlobalTurnStateMachineCase17(this);
    break;
  case 0x19:
    AdvanceGlobalTurnStateMachineCase19(this);
    break;

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

  case 0x71:
  case 0x72:
    turnStateCode = 4;
    PostTurnEventCodeMessage2420();
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
