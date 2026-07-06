#include "game/TMultiplayerMgr.h"

#include "decomp_types.h"
#include "game/CString.h"
#include "game/mapped_flavor_text.h"
#include "game/NetMessage.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMinor.h"
#include "game/TCity.h"
#include "game/TNetMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TViewMgr.h"
#include "game/TApplication.h"
#include "game/TAssetMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TCountry.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include <cstdlib>
#include <cstring>

// Leaf helpers reached through ILT thunks / autogen stubs. They are genuine __cdecl free
// functions (verified against the disassembly — none consume ECX as `this` on entry; the
// ECX loads before some calls are optimizer reuse, not a this-arg). Declared extern in the
// generic repo form per Hard Rule 9 and cast to their real typed signatures at the call sites.
extern undefined4 NoOpInitializeGlobalTurnEventQueueManager();
extern undefined4 ResetTurnEventQueueRuntimeRecordBuffer();
extern undefined4 LoadProfileStringAndAssignSharedRef();
extern undefined4 AssignStringSharedRefFromPointer();

// Forward decl: real definition (with its // FUNCTION: marker) sits address-ordered
// further down this file, near TMultiplayerMgr's other 0x5exxxx-adjacent members.
static char ReturnTrueRuntimeCredentialInitStub();

// Profile-section string literals.
extern "C" const char s_PlayerName_0069801c[];
extern "C" const char s_GameName_00698010[];

// SYNTHETIC: IMPERIALISM 0x005425d0
// TMultiplayerMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00542650
// TMultiplayerMgr::GetRuntimeClass

// Binary descriptor base is TObject (0x694eb8), not TEventHandler — original macro arg.
IMPLEMENT_DYNCREATE(TMultiplayerMgr, TObject)

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr()
    : TEventHandler(), gameNameString(), defaultNationTextSlots(), nationDisplayNameSlots(),
      playerNameString(), playerNameMirror(), fieldb8() {
  InitializeUiResourceEntryBaseHeaderDefaults();
  memset(nationStatusControlSlots, 0, sizeof(nationStatusControlSlots));
  field40 = 0;
  primaryTurnEventQueueHead = 0;
  secondaryTurnEventQueueHead = 0;
  sessionPhaseTag = 0x6e616461;
  fieldF4 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005427e0
// TMultiplayerMgr::`scalar deleting destructor'
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
undefined TMultiplayerMgr::InitializeMultiplayerManagerForSessionContext(CString param_1) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  field10 = reinterpret_cast<int>(static_cast<LPCSTR>(param_1));
  diplomacyQueueContext = 0;
  sessionReadyFlag = 0;
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;

  TNetMgr* queueStorage = new TNetMgr();
  g_pNetMgr006a6014 = queueStorage;
  reinterpret_cast<void (*)()>(NoOpInitializeGlobalTurnEventQueueManager)();

  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);

  for (int i = 0; i < kNationSlotCount; ++i) {
    nationSessionIds[0] = 0;
    nationStatusTags[0] = 0x756e6173;
    nationDisplayNameSlots[i] = loadedString;
    reinterpret_cast<void (*)(CString*)>(AssignStringSharedRefFromPointer)(
        &nationDisplayNameSlots[i]);
  }

  queueSyncDword = 0;
  activeNationSlotIndex = -1;
  pendingNationSlotIndex = -1;
  reinterpret_cast<void (*)()>(ResetTurnEventQueueRuntimeRecordBuffer)();

  GenerateMappedFlavorTextByCurrentContextNation(&playerNameString);
  reinterpret_cast<void (*)(CString*, const char*, const char*)>(
      LoadProfileStringAndAssignSharedRef)(&loadedString, s_PlayerName_0069801c,
                                           static_cast<LPCSTR>(playerNameString));
  playerNameString = loadedString;
  playerNameMirror = playerNameString;

  GenerateMappedFlavorTextByCurrentContextNation(&gameNameString);
  reinterpret_cast<void (*)(CString*, const char*, const char*)>(
      LoadProfileStringAndAssignSharedRef)(&loadedString, s_GameName_00698010,
                                           static_cast<LPCSTR>(gameNameString));
  gameNameString = loadedString;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00542b10
void TMultiplayerMgr::Free() {}

// FUNCTION: IMPERIALISM 0x00542be0
void TMultiplayerMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00542ff0
void TMultiplayerMgr::WriteTo(TStream* stream) {
  (void)stream;
}

struct TurnEvent3Mode18Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
};

// FUNCTION: IMPERIALISM 0x00544540
void TMultiplayerMgr::EnsureGameFlowStateAndPostTurnEvent5E5() {
  TMultiplayerMgr* self = this;
  if (self == 0) {
    self = new TMultiplayerMgr();
    g_pGameFlowState = self;
    if (self != 0) {
      self->InitializeMultiplayerManagerForSessionContext(CString());
    }
    self = g_pGameFlowState;
  }
  if (self == 0) {
    return;
  }

  ReturnTrueRuntimeCredentialInitStub();
  g_pGlobalUiRootController->InstallCohandler(self, 1);
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e5);
  self->sessionPhaseTag = 0x70726570; // 'prep'
}

// FUNCTION: IMPERIALISM 0x005446a0
void TMultiplayerMgr::EmitTurnEvent3Mode18WithActiveNation() {
  TurnEvent3Mode18Packet packet;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.eventCode = 3;
  packet.messageLength = 0x18;
  g_pNetMgr006a6014->Send(&packet, 1);
}

// FUNCTION: IMPERIALISM 0x00544e30
char TMultiplayerMgr::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  return 0;
}

// ---------------------------------------------------------------------------
// Turn-event emitters. Each builds a 'time'-tagged NetMessage-derived packet on
// the stack and hands it to TNetMgr::Send (queueOnly per callsite). `this` is
// unused, exactly as in the original __thiscall bodies.
// ---------------------------------------------------------------------------

struct TurnEvent12Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  short shortA;
  short shortB;
};

// Ghidra pseudo-types used by the promoted state machine below. `code` is Ghidra's
// raw-code-byte type (used both as a scalar and as a code pointer); the slot type is a
// byte cursor so `param_1 + offset` stays a byte offset into the object.
typedef unsigned char code;
typedef unsigned char CObject_slot_0x04_0x04;
typedef unsigned int undefined3;
typedef signed char sbyte;

// Minimal stand-in for the CString locals that the raw decompile touches only via
// their leading char* buffer (m_pchData at offset 0). Real string semantics are not
// required to reproduce this state machine's control flow.
struct GhStr {
  char* m_pchData;
};

// Ghidra bit-concatenation intrinsics (compile-only; exact widths are not load-bearing
// here). CONCAT31(hi,lo) packs a 3-byte high value with a 1-byte low value, etc.
#define CONCAT11(hi, lo)                                                                           \
  ((unsigned short)(((unsigned int)(unsigned char)(hi) << 8) | (unsigned char)(lo)))
#define CONCAT13(hi, lo)                                                                           \
  (((unsigned int)(unsigned char)(hi) << 24) | ((unsigned int)(lo) & 0xffffffu))
#define CONCAT31(hi, lo) (((unsigned int)(hi) << 8) | (unsigned char)(lo))
#define builtin_strncpy(d, s, n) memcpy((d), (s), (n))

// Ghidra's `operator_new()` (size folded away by the optimizer). A real allocation is
// enough to keep the reconstructed pointer flow compiling and linking.
static void* operator_new(void) {
  return malloc(0x400);
}

// FUNCTION: IMPERIALISM 0x00545940
undefined4 TMultiplayerMgr::ProcessDiplomacyTurnStateEventStateMachine(NetMessage* packet) {
  CObject_slot_0x04_0x04* param_1 = reinterpret_cast<CObject_slot_0x04_0x04*>(this);
  undefined4* param_2 = reinterpret_cast<undefined4*>(packet);
  GhStr* thisStr;
  char cVar1;
  code cVar2;
  word wVar3;
  undefined2 uVar4;
  CObject* this_00;
  void** pCVar5;
  TMinor* pTVar6;
  TGreatPower* pTVar7;
  void** pTVar8;
  byte bVar9;
  bool bVar10;
  undefined uVar11;
  char cVar12;
  undefined1 uVar13;
  short sVar14;
  short sVar15;
  undefined4 uVar16;
  char* pcVar17;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int* piVar18;
  TGreatPower** ppTVar19;
  word* pwVar20;
  undefined2* puVar21;
  undefined4* puVar22;
  word* pwVar23;
  HGLOBAL hMem;
  int* piVar24;
  char* pcVar25;
  word* pwVar26;
  undefined2* puVar27;
  void** ppvVar28;
  undefined2* puVar29;
  uint uVar30;
  uint uVar31;
  code* pcVar32;
  undefined4* puVar33;
  int iVar34;
  int iVar35;
  uint uVar36;
  char* unaff_EBP;
  code* unaff_ESI;
  TCountry** ppTVar37;
  undefined4* puVar38;
  undefined4* puVar39;
  GhStr* unaff_EDI;
  char* pcVar40;
  TCity* pTVar41;
  GhStr CVar42;
  TDiplomacyMgr* pTVar43;
  undefined4* unaff_FS_OFFSET;
  GhStr local_1d4;
  GhStr local_1d0;
  undefined4 uStack_1cc;
  GhStr local_1c8;
  GhStr local_1c4;
  GhStr local_1c0;
  GhStr local_1bc;
  undefined4 local_1b8[5];
  undefined1 local_1a4[4];
  undefined4 local_1a0;
  int local_19c;
  char local_198[24];
  undefined1 auStack_180[9];
  char local_177[31];
  GhStr CStack_158;
  GhStr local_154;
  GhStr CStack_150;
  GhStr local_14c;
  GhStr CStack_148;
  GhStr local_144[2];
  undefined4 uStack_13c;
  undefined4 uStack_138;
  undefined4 uStack_134;
  undefined4 uStack_130;
  undefined4 uStack_12c;
  undefined4 local_128;
  char local_124[4];
  undefined4 local_120;
  char local_11c[248];
  char cStack_24;
  undefined1 uStack_23;
  undefined4 uStack_1c;
  undefined1 uStack_18;
  undefined1 uStack_14;
  undefined1 local_10;
  undefined1 local_f;
  undefined4 local_c;
  undefined1* puStack_8;
  undefined4 local_4;
  char stack0xfffffde0[512];
  char stack0xfffffe00[512];
  char stack0xfffffe1c[512];

  local_4 = 0xffffffff;
  puStack_8 = reinterpret_cast<undefined1*>(0x00634baf);
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (undefined4)&local_c;
  local_1d0.m_pchData = (char*)param_1;
  switch (*param_2) {
  case 1:
    uVar16 = 1;
    *(undefined4*)(param_1 + 0xe8) = param_2[6];
    break;
  case 2:
    if (*(char*)(param_2 + 8) == '\0') {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x403aad)();
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 3:
    *(undefined4*)(param_1 + 0xd8) = 0x676f696e;
    *(undefined4*)(param_1 + 0xec) = 0xffffffff;
    *(undefined4*)(param_1 + 0xf0) = 0xffffffff;
    iVar35 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
    iVar34 = 0;
    piVar24 = (int*)((int)g_pGameFlowState + 0x48);
    do {
      if (*piVar24 == iVar35)
        goto LAB_00546c48;
      iVar34 = iVar34 + 1;
      piVar24 = piVar24 + 1;
    } while (iVar34 < 7);
    iVar34 = -1;
  LAB_00546c48:
    if (iVar34 == -1) {
      pcVar25 = (char*)operator_new();
      local_4 = 0x12;
      local_1c4.m_pchData = pcVar25;
      if (pcVar25 != (char*)0x0) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
        *reinterpret_cast<void**>(pcVar25) = 0;
      }
      local_4 = 0xffffffff;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405ee3)();
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(pcVar25);
      uVar16 = 1;
    } else {
      sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
      iVar35 = (int)sVar15;
      if (iVar35 == -1) {
        iVar35 = (int)(char)param_1[0xdc];
      }
      *(undefined4*)(param_1 + iVar35 * 4 + 0xbc) = 0x62757379;
      local_1b8[4] = 0x74696d65;
      local_1a4[0] = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
      local_1b8[1] = 0;
      local_1b8[0] = 0x25;
      local_1b8[3] = 0x34;
      puVar22 = &local_1a0;
      for (iVar34 = 7; iVar34 != 0; iVar34 = iVar34 + -1) {
        *puVar22 = 0x756e6b6e;
        puVar22 = puVar22 + 1;
      }
      local_1b8[2] = 0;
      (&local_1a0)[iVar35] = 0x62757379;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
      g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
      uVar16 = 1;
    }
    break;
  default:
    uVar16 = 0;
    break;
  case 8:
    cVar12 = *(char*)(param_2 + 6);
    local_1d4.m_pchData = (char*)(int)cVar12;
    if (local_1d4.m_pchData == (char*)0xffffffff) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405682)();
    } else if (*(int*)(param_1 + (int)local_1d4.m_pchData * 4 + 0x48) != 0) {
      iVar35 = param_2[1];
      if (*(int*)(param_1 + (int)local_1d4.m_pchData * 4 + 0x48) == iVar35) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a45)();
        local_1b8[1] = 0;
        uVar36 = 0xffffffff;
        pcVar25 = (char*)((int)param_2 + 0x19);
        do {
          pcVar17 = pcVar25;
          if (uVar36 == 0)
            break;
          uVar36 = uVar36 - 1;
          pcVar17 = pcVar25 + 1;
          cVar1 = *pcVar25;
          pcVar25 = pcVar17;
        } while (cVar1 != '\0');
        uVar36 = ~uVar36;
        local_1b8[2] = 0;
        local_1b8[3] = 100;
        local_1b8[0] = 9;
        local_1a0 = CONCAT31(((unsigned int)(local_1a0) >> 8 & 0xffffff), cVar12);
        pcVar25 = pcVar17 + -uVar36;
        pcVar17 = local_198;
        for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
          *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
          pcVar25 = pcVar25 + 4;
          pcVar17 = pcVar17 + 4;
        }
        for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
          *pcVar17 = *pcVar25;
          pcVar25 = pcVar25 + 1;
          pcVar17 = pcVar17 + 1;
        }
        uVar36 = 0xffffffff;
        pcVar25 = (char*)((int)param_2 + 0x3a);
        do {
          pcVar17 = pcVar25;
          if (uVar36 == 0)
            break;
          uVar36 = uVar36 - 1;
          pcVar17 = pcVar25 + 1;
          cVar12 = *pcVar25;
          pcVar25 = pcVar17;
        } while (cVar12 != '\0');
        uVar36 = ~uVar36;
        pcVar25 = pcVar17 + -uVar36;
        pcVar17 = local_177;
        for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
          *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
          pcVar25 = pcVar25 + 4;
          pcVar17 = pcVar17 + 4;
        }
        for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
          *pcVar17 = *pcVar25;
          pcVar25 = pcVar25 + 1;
          pcVar17 = pcVar17 + 1;
        }
        local_19c = iVar35;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
        uVar16 = 1;
      } else {
        builtin_strncpy(local_11c + 4, "emit", 4);
        local_11c[8] = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
        local_124[0] = '\0';
        local_124[1] = '\0';
        local_124[2] = '\0';
        local_124[3] = '\0';
        local_128 = 0xc;
        local_120 = 0;
        local_10 = 0xff;
        local_11c[0] = '\x1c';
        local_11c[1] = '\x01';
        local_11c[2] = '\0';
        local_11c[3] = '\0';
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
        local_120 = param_2[1];
        local_f = 0xff;
        ((void)0);
        local_4 = 2;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        uVar36 = 0xffffffff;
        do {
          pcVar25 = unaff_EBP;
          if (uVar36 == 0)
            break;
          uVar36 = uVar36 - 1;
          pcVar25 = unaff_EBP + 1;
          cVar12 = *unaff_EBP;
          unaff_EBP = pcVar25;
        } while (cVar12 != '\0');
        uVar36 = ~uVar36;
        pcVar25 = pcVar25 + -uVar36;
        pcVar17 = local_124 + 8;
        for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
          *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
          pcVar25 = pcVar25 + 4;
          pcVar17 = pcVar17 + 4;
        }
        for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
          *pcVar17 = *pcVar25;
          pcVar25 = pcVar25 + 1;
          pcVar17 = pcVar17 + 1;
        }
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
      }
      break;
    }
    local_1c0.m_pchData = (char*)0x0;
    pcVar32 = (code*)(local_1d0.m_pchData + 0x48);
    do {
      if (*(int*)pcVar32 == param_2[1]) {
        *(int*)pcVar32 = 0;
        *(int*)(pcVar32 + 0x74) = 0x756e6173;
        pcVar25 = (*reinterpret_cast<char**>(0x0065bf18));
        local_1bc.m_pchData = (*reinterpret_cast<char**>(0x0065bf18));
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a45)();
        local_1b8[1] = 0;
        local_1a0 = CONCAT31(((unsigned int)(local_1a0) >> 8 & 0xffffff),
                             ((unsigned int)(local_1c0.m_pchData) & 0xff));
        local_1b8[2] = 0;
        uVar36 = 0xffffffff;
        do {
          pcVar17 = pcVar25;
          if (uVar36 == 0)
            break;
          uVar36 = uVar36 - 1;
          pcVar17 = pcVar25 + 1;
          cVar12 = *pcVar25;
          pcVar25 = pcVar17;
        } while (cVar12 != '\0');
        uVar36 = ~uVar36;
        local_19c = 0;
        local_1b8[3] = 100;
        local_1b8[0] = 9;
        pcVar25 = pcVar17 + -uVar36;
        pcVar17 = local_198;
        for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
          *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
          pcVar25 = pcVar25 + 4;
          pcVar17 = pcVar17 + 4;
        }
        for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
          *pcVar17 = *pcVar25;
          pcVar25 = pcVar25 + 1;
          pcVar17 = pcVar17 + 1;
        }
        uVar36 = 0xffffffff;
        CVar42.m_pchData = local_1bc.m_pchData;
        do {
          pcVar25 = CVar42.m_pchData;
          if (uVar36 == 0)
            break;
          uVar36 = uVar36 - 1;
          pcVar25 = CVar42.m_pchData + 1;
          cVar12 = *CVar42.m_pchData;
          CVar42.m_pchData = pcVar25;
        } while (cVar12 != '\0');
        uVar36 = ~uVar36;
        pcVar25 = pcVar25 + -uVar36;
        pcVar17 = local_177;
        for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
          *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
          pcVar25 = pcVar25 + 4;
          pcVar17 = pcVar17 + 4;
        }
        for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
          *pcVar17 = *pcVar25;
          pcVar25 = pcVar25 + 1;
          pcVar17 = pcVar17 + 1;
        }
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
      }
      CVar42.m_pchData = local_1d4.m_pchData;
      pcVar32 = pcVar32 + 4;
      local_1c0.m_pchData = local_1c0.m_pchData + 1;
    } while ((int)local_1c0.m_pchData < 7);
    if (local_1d4.m_pchData != (char*)0xffffffff) {
      uVar16 = param_2[1];
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a45)();
      uVar36 = 0xffffffff;
      pcVar25 = (char*)((int)param_2 + 0x19);
      do {
        pcVar17 = pcVar25;
        if (uVar36 == 0)
          break;
        uVar36 = uVar36 - 1;
        pcVar17 = pcVar25 + 1;
        cVar12 = *pcVar25;
        pcVar25 = pcVar17;
      } while (cVar12 != '\0');
      local_1b8[1] = 0;
      local_1b8[0] = 9;
      uVar36 = ~uVar36;
      local_1b8[2] = 0;
      local_1b8[3] = 100;
      local_1a0 = CONCAT31(((unsigned int)(local_1a0) >> 8 & 0xffffff), (char)CVar42.m_pchData);
      pcVar25 = pcVar17 + -uVar36;
      pcVar17 = local_198;
      for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
        *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
        pcVar25 = pcVar25 + 4;
        pcVar17 = pcVar17 + 4;
      }
      for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
        *pcVar17 = *pcVar25;
        pcVar25 = pcVar25 + 1;
        pcVar17 = pcVar17 + 1;
      }
      uVar36 = 0xffffffff;
      pcVar25 = (char*)((int)param_2 + 0x3a);
      do {
        pcVar17 = pcVar25;
        if (uVar36 == 0)
          break;
        uVar36 = uVar36 - 1;
        pcVar17 = pcVar25 + 1;
        cVar12 = *pcVar25;
        pcVar25 = pcVar17;
      } while (cVar12 != '\0');
      uVar36 = ~uVar36;
      pcVar25 = pcVar17 + -uVar36;
      pcVar17 = local_177;
      for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
        *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
        pcVar25 = pcVar25 + 4;
        pcVar17 = pcVar17 + 4;
      }
      for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
        *pcVar17 = *pcVar25;
        pcVar25 = pcVar25 + 1;
        pcVar17 = pcVar17 + 1;
      }
      local_19c = uVar16;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 9:
    cVar2 = *(code*)(param_2 + 6);
    if (cVar2 != (code)0xf3) {
      pcVar25 = (char*)param_2[7];
      iVar35 = (int)(char)cVar2;
      local_1d4.m_pchData = pcVar25;
      (reinterpret_cast<GhStr*>(&local_154)->m_pchData = (char*)((char*)(param_2 + 8)));
      CVar42.m_pchData = local_1d0.m_pchData;
      local_4 = 3;
      ((*reinterpret_cast<GhStr*>((GhStr*)(local_1d0.m_pchData + iVar35 * 4 + 0x78))) =
           (*reinterpret_cast<GhStr*>(&local_154)));
      local_4 = 0xffffffff;
      ((void)0);
      (reinterpret_cast<GhStr*>(&local_14c)->m_pchData = (char*)((char*)((int)param_2 + 0x41)));
      thisStr = (GhStr*)(CVar42.m_pchData + iVar35 * 4 + 0x94);
      local_4 = 4;
      ((*reinterpret_cast<GhStr*>(thisStr)) = (*reinterpret_cast<GhStr*>(&local_14c)));
      local_4 = 0xffffffff;
      ((void)0);
      /* WARNING: Load size is inaccurate */
      local_1bc.m_pchData = (char*)(int)CVar42.m_pchData[iVar35 * 4 + 0x48];
      *(char**)(CVar42.m_pchData + iVar35 * 4 + 0x48) = pcVar25;
      pcVar17 = (char*)reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
      if ((pcVar25 == pcVar17) && (pcVar25 != (char*)0x0)) {
        uStack_1cc = CONCAT13(1, (undefined3)uStack_1cc);
        CVar42.m_pchData[0xdc] = (char)cVar2;
      } else {
        uStack_1cc = uStack_1cc & 0xffffff;
      }
      ((void)0);
      local_4 = 5;
      if (pcVar25 == (char*)0x0) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        *(undefined4*)(CVar42.m_pchData + iVar35 * 4 + 0xbc) = 0x756e6173;
      } else {
        ((*reinterpret_cast<GhStr*>(&local_1c0)) = (*reinterpret_cast<GhStr*>(thisStr)));
        if ((*(int*)(CVar42.m_pchData + 0xd8) == 0x676f696e) &&
            (sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)(), sVar15 != -1)) {
          bVar9 = 1;
        } else {
          bVar9 = 0;
        }
        *(uint*)(CVar42.m_pchData + iVar35 * 4 + 0xbc) = (-(uint)bVar9 & 0xf0100f00) + 0x72656479;
      }
      ((*reinterpret_cast<GhStr*>(thisStr)) = (*reinterpret_cast<GhStr*>(&local_1c0)));
      ((*reinterpret_cast<GhStr*>((GhStr*)(CVar42.m_pchData + iVar35 * 4 + 0x78))) =
           (*reinterpret_cast<GhStr*>(thisStr)));
      this_00 = *(CObject**)(CVar42.m_pchData + 0x40);
      if ((this_00 == (CObject*)0x0) ||
          (iVar35 = this_00->IsKindOf((CRuntimeClass*)0), iVar35 == 0)) {
        iVar35 = 0;
      } else {
        iVar35 = *(int*)(CVar42.m_pchData + 0x40);
      }
      if (iVar35 != 0) {
        local_1d0.m_pchData = (char*)((*reinterpret_cast<void***>(this_00))[37]);
        uVar11 = reinterpret_cast<undefined4(__cdecl*)(...)>(local_1d0.m_pchData)();
        iVar35 = *(int*)CONCAT31(extraout_var, uVar11);
        reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a2c)();
        local_10 = 6;
        reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c8)))();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x40263a)();
        pcVar25 = (char*)reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
        if ((local_1bc.m_pchData == pcVar25) ||
            (pcVar25 = (char*)reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)(),
             local_1d4.m_pchData == pcVar25)) {
          iVar35 = 6;
          pcVar32 = (code*)(CVar42.m_pchData + 0x60);
          do {
            iVar34 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
            if (*(int*)pcVar32 == iVar34)
              break;
            iVar35 = iVar35 + -1;
            pcVar32 = pcVar32 + -4;
          } while (-1 < iVar35);
          piVar24 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(local_1d0.m_pchData)();
          iVar34 = *piVar24;
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar34 + 0xc)))();
          piVar24[0x1a] = iVar35;
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x40686b)();
          reinterpret_cast<undefined4(__cdecl*)(...)>(
              *reinterpret_cast<void**>((iVar34 + 0x128)))();
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x401d70)();
          local_10 = 7;
          reinterpret_cast<undefined4(__cdecl*)(...)>(
              *reinterpret_cast<void**>((unaff_ESI + 0x110)))();
          piVar24 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(unaff_ESI)();
          iVar34 = *piVar24;
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar34 + 0xc)))();
          if (-1 < iVar35) {
            reinterpret_cast<undefined4(__cdecl*)(...)>(
                *reinterpret_cast<void**>((iVar34 + 0x1c8)))();
          }
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar34 + 0xa4)))();
          local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 6);
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x004948b0)();
        }
        if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
          bVar10 = false;
          local_1c8.m_pchData = (char*)0x0;
          pcVar32 = (code*)(CVar42.m_pchData + 0x48);
          iVar35 = 7;
          do {
            if (*(int*)pcVar32 != 0) {
              local_1c8.m_pchData = local_1c8.m_pchData + 1;
              iVar34 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
              if (*(int*)pcVar32 == iVar34) {
                bVar10 = true;
              }
            }
            pcVar32 = pcVar32 + 4;
            iVar35 = iVar35 + -1;
          } while (iVar35 != 0);
          if (((int)local_1c8.m_pchData < 2) || (!bVar10)) {
            bVar10 = false;
          } else {
            bVar10 = true;
          }
          piVar24 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(local_1d0.m_pchData)();
          iVar35 = *piVar24;
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
          ((void)0);
          pcVar32 = (code*)0x2759;
          puStack_8 = (undefined1*)CONCAT31(((unsigned int)(puStack_8) >> 8 & 0xffffff), 8);
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
          if (bVar10) {
            ((*reinterpret_cast<GhStr*>((GhStr*)(piVar24 + 0x25))) =
                 (*reinterpret_cast<GhStr*>((GhStr*)reinterpret_cast<char*>(stack0xfffffe1c))));
            reinterpret_cast<undefined4(__cdecl*)(...)>(
                *reinterpret_cast<void**>((iVar35 + 0xe4)))();
          }
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xa8)))();
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xa4)))();
          *(undefined2*)((int)piVar24 + 0x9a) = 0x2b6c;
          *(undefined2*)(piVar24 + 0x27) = 0x2b6b;
          *(undefined2*)(piVar24 + 0x26) = 0xc;
          piVar24 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(pcVar32)();
          iVar35 = *piVar24;
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
          reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xa4)))();
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x407ce8)();
          pCVar5 = *reinterpret_cast<void***>(this_00);
          reinterpret_cast<undefined4(__cdecl*)(...)>(pCVar5[3])();
          reinterpret_cast<undefined4(__cdecl*)(...)>(pCVar5[114])();
          local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 6);
          ((void)0);
        }
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 5);
        ((void)0);
      }
      local_4 = 0xffffffff;
      ((void)0);
      uVar16 = 1;
      break;
    }
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
      pcVar25 = *(char**)(param_1 + 0xb4);
      pcVar17 = *(char**)(param_1 + 0xb0);
      uVar16 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
      *reinterpret_cast<unsigned short*>(&(local_1bc.m_pchData)) = (short)(char)param_1[0xdc];
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a45)();
      uVar36 = 0xffffffff;
      local_1a0 = CONCAT31(((unsigned int)(local_1a0) >> 8 & 0xffffff),
                           ((unsigned int)(local_1bc.m_pchData) & 0xff));
      do {
        pcVar40 = pcVar17;
        if (uVar36 == 0)
          break;
        uVar36 = uVar36 - 1;
        pcVar40 = pcVar17 + 1;
        cVar12 = *pcVar17;
        pcVar17 = pcVar40;
      } while (cVar12 != '\0');
      local_1b8[0] = 9;
      local_1b8[1] = 0;
      uVar36 = ~uVar36;
      local_1b8[2] = 0;
      local_1b8[3] = 100;
      pcVar17 = pcVar40 + -uVar36;
      pcVar40 = local_198;
      for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
        *(undefined4*)pcVar40 = *(undefined4*)pcVar17;
        pcVar17 = pcVar17 + 4;
        pcVar40 = pcVar40 + 4;
      }
      for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
        *pcVar40 = *pcVar17;
        pcVar17 = pcVar17 + 1;
        pcVar40 = pcVar40 + 1;
      }
      uVar36 = 0xffffffff;
      do {
        pcVar17 = pcVar25;
        if (uVar36 == 0)
          break;
        uVar36 = uVar36 - 1;
        pcVar17 = pcVar25 + 1;
        cVar12 = *pcVar25;
        pcVar25 = pcVar17;
      } while (cVar12 != '\0');
      uVar36 = ~uVar36;
      pcVar25 = pcVar17 + -uVar36;
      pcVar17 = local_177;
      for (uVar30 = uVar36 >> 2; uVar30 != 0; uVar30 = uVar30 - 1) {
        *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
        pcVar25 = pcVar25 + 4;
        pcVar17 = pcVar17 + 4;
      }
      for (uVar36 = uVar36 & 3; uVar36 != 0; uVar36 = uVar36 - 1) {
        *pcVar17 = *pcVar25;
        pcVar25 = pcVar25 + 1;
        pcVar17 = pcVar17 + 1;
      }
      local_19c = uVar16;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 10:
    if (g_pSimMgr->stateFlag114 == 0) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(
          (*reinterpret_cast<void***>(g_pGlobalMapState))[76])();
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x40108c)();
    }
    *(uint*)(param_1 + 0xe8) = *(uint*)(param_1 + 0xe8) & ~(1 << (*(byte*)(param_2 + 7) & 0x1f));
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a45)();
      local_1a0 = *(uint*)(param_1 + 0xe8);
    LAB_00545aa0:
      local_1b8[3] = 0x1c;
      local_1b8[2] = 0;
      local_1b8[1] = 0;
      local_1b8[0] = 1;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
      if ((*(int*)(param_1 + 0xe8) == 0) && (*(int*)(param_1 + 0xf0) != -1)) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401d7f)();
        uVar16 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0xb:
    iVar35 = 0;
    puVar22 = param_2 + 7;
    ppTVar37 = g_apTerrainTypeDescriptorTable;
    pcVar25 = (char*)((int)param_2 + 0x341);
    do {
      sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
      if ((iVar35 != sVar15) &&
          (cVar12 = (*ppTVar37)->ShouldDispatchImmediatelySlot28(), cVar12 != '\0')) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>((*ppTVar37)))[41])();
        (reinterpret_cast<GhStr*>(&CStack_158)->m_pchData = (char*)(pcVar25));
        local_c = 0;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x40308f)();
        local_4 = 0xffffffff;
        ((void)0);
        (reinterpret_cast<GhStr*>(&CStack_148)->m_pchData = (char*)(pcVar25));
        local_4 = 1;
        ((*reinterpret_cast<GhStr*>((GhStr*)(reinterpret_cast<char*>((*ppTVar37)) + 0x8))) =
             (*reinterpret_cast<GhStr*>(&CStack_148)));
        local_4 = 0xffffffff;
        ((void)0);
        if (g_pSimMgr->stateFlag114 == 0) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(
              (*reinterpret_cast<void***>(g_pGlobalMapState))[76])();
        }
      }
      iVar34 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x4076a8)();
      puVar38 = puVar22 + 0x187;
      ppTVar37 = ppTVar37 + 1;
      iVar35 = iVar35 + 1;
      puVar22 = (undefined4*)((int)puVar22 + 2);
      pcVar25 = pcVar25 + 0x17;
      *(undefined2*)(iVar34 + 0x14) = *(undefined2*)puVar38;
    } while ((int)ppTVar37 < 0x6a436c);
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x409859)();
    uVar16 = 1;
    break;
  case 0xc:
    sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
    local_1d4.m_pchData = (char*)(int)sVar15;
    if (local_1d4.m_pchData == (char*)0xffffffff) {
      iVar35 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
      local_1d4.m_pchData = (char*)0x0;
      piVar24 = (int*)((int)g_pGameFlowState + 0x48);
      do {
        if (*piVar24 == iVar35)
          goto LAB_005464f4;
        local_1d4.m_pchData = local_1d4.m_pchData + 1;
        piVar24 = piVar24 + 1;
      } while ((int)local_1d4.m_pchData < 7);
      local_1d4.m_pchData = (char*)0xffffffff;
    LAB_005464f4:
      if (local_1d4.m_pchData != (char*)0xffffffff)
        goto LAB_005464fd;
    } else {
    LAB_005464fd:
      if ((*(byte*)(param_2 + 0x46) & (byte)(1 << ((byte)local_1d4.m_pchData & 0x1f))) == 0)
        goto LAB_005485d8;
    }
    CVar42.m_pchData = local_1d4.m_pchData;
    pcVar25 = (char*)(int)*(char*)((int)param_2 + 0x119);
    local_1c8.m_pchData = pcVar25;
    (reinterpret_cast<GhStr*>(&local_1bc)->m_pchData = (char*)((char*)(param_2 + 6)));
    local_4 = 9;
    ((void)0);
    *(unsigned char*)&(local_4) = 10;
    ((void)0);
    local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0xb);
    if ((pcVar25 == (char*)0xffffffff) || (pcVar25 == CVar42.m_pchData)) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x40619f)();
    } else {
      reinterpret_cast<undefined4(__cdecl*)(...)>((*reinterpret_cast<void***>(g_pSimMgr))[33])();
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x40988b)();
    }
    ((unsigned char*)&(CStack_148.m_pchData))[2] = 0;
    ((unsigned char*)&(CStack_148.m_pchData))[3] = 0;
    *(unsigned char*)&(local_144[0].m_pchData) = 0;
    ((unsigned char*)&(local_144[0].m_pchData))[1] = 0;
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x005c3e80)();
    piVar24 = (int*)g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x7e4);
    if (piVar24 == (int*)0x0) {
      MessageBoxA((HWND)0x0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x4057a4)();
    }
    iVar35 = *piVar24;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1a0)))();
    iVar34 =
        reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1b8)))();
    if (iVar34 != 0) {
      *(undefined4*)(iVar34 + 0x14) = 0x6f6b6179;
    }
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        *reinterpret_cast<void**>((*reinterpret_cast<char**>(g_pUiRuntimeContext) + 0x44)))();
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xf0)))();
    pcVar32 = *(code**)(iVar35 + 0x94);
    piVar18 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(pcVar32)();
    iVar35 = *piVar18;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
    if (piVar18 == (int*)0x0) {
      MessageBoxA((HWND)0x0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x4057a4)();
    }
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c8)))();
    iVar34 = 0x636f6174;
    piVar18 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(pcVar32)();
    iVar35 = *piVar18;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
    if (piVar18 == (int*)0x0) {
      MessageBoxA((HWND)0x0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x4057a4)();
    }
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c8)))();
    piVar18 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(pcVar32)(0x7469746c);
    iVar35 = *piVar18;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
    if (piVar18 == (int*)0x0) {
      MessageBoxA((HWND)0x0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x4057a4)(reinterpret_cast<char*>(0x00698040),
                                                            0x807);
    }
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1b4)))(
        auStack_180, 0);
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c4)))(1, 0);
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c8)))(
        reinterpret_cast<char*>(stack0xfffffde0), 0);
    piVar18 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(pcVar32)();
    iVar35 = *piVar18;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 500)))(
        iVar34, *(undefined4*)(iVar34 + -8));
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1e4)))(
        local_1a4, 0);
    *(undefined1*)((int)g_pGameFlowState + 0x68) = 0;
    piVar18 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(pcVar32)(0x636e636c);
    iVar35 = *piVar18;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xc)))();
    piVar18[7] = 0x72737670;
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xa4)))(1, 0);
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xa8)))(1, 0);
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c8)))(0x53a,
                                                                                             0);
    iVar35 = *piVar24;
    iVar34 =
        reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1ac)))();
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0xa0)))();
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((iVar35 + 0x1c)))();
    if (iVar34 == 0x72737670) {
      pcVar25 = (char*)operator_new();
      *(unsigned char*)&(local_4) = 0xc;
      local_1c4.m_pchData = pcVar25;
      if (pcVar25 == (char*)0x0) {
        pcVar25 = (char*)0x0;
      } else {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
        *reinterpret_cast<void**>(pcVar25) = 0;
      }
      *(char**)(pcVar25 + 0x18) = local_1c8.m_pchData;
      local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0xb);
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405ee3)();
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(pcVar25);
    }
    *(unsigned char*)&(local_4) = 10;
    *(char*)((int)g_pGameFlowState + 0x68) = ((unsigned int)(uStack_1cc) >> 24 & 0xff);
    ((void)0);
    local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 9);
    ((void)0);
    local_4 = 0xffffffff;
    ((void)0);
    uVar16 = 1;
    break;
  case 0xd:
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x407e82)();
    uVar16 = 1;
    break;
  case 0xe:
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x401668)();
    g_pSimMgr->useLocalizedNameTables68 = *(undefined1*)((int)param_2 + 0x65);
    (reinterpret_cast<GhStr*>(local_144)->m_pchData = (char*)((char*)((int)param_2 + 0x3a)));
    local_4 = 0xd;
    ((*reinterpret_cast<GhStr*>((GhStr*)(param_1 + 0x74))) =
         (*reinterpret_cast<GhStr*>(local_144)));
    local_4 = 0xffffffff;
    ((void)0);
    uVar36 = param_2[0x18];
    *(uint*)(param_1 + 0xe0) = uVar36;
    *(undefined4*)(param_1 + 100) = param_2[0x17];
    *(undefined4*)(param_1 + 0xd8) = 0x696e6974;
    if (uVar36 == 0x6c6f6164) {
      cVar12 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x408d78)();
      if (cVar12 == '\0') {
        ((void)0);
        local_4 = 0xe;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        local_1d0.m_pchData = reinterpret_cast<char*>(stack0xfffffe00);
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x4076b7)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x005d5b00)();
        pcVar25 = (char*)operator_new();
        uStack_14 = 0xf;
        local_1d4.m_pchData = pcVar25;
        if (pcVar25 != (char*)0x0) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
          *reinterpret_cast<void**>(pcVar25) = 0;
        }
        uStack_14 = 0xe;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405ee3)();
        g_pGlobalUiRootController->DispatchUiSelectionToHandler(pcVar25);
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
      } else {
        *(undefined4*)((int)g_pGameFlowState + 0x40) = 0;
        *(undefined4*)((int)g_pGameFlowState + 0xd8) = 0x676f696e;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x409859)();
        uVar16 = 1;
      }
      break;
    }
    if (uVar36 == 0x72616e64) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x404cd2)();
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405704)();
    } else {
      if ((uVar36 < 0x73636e30) || (0x73637a39 < uVar36))
        goto LAB_005485d8;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x404cd2)();
      cVar12 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x4082ba)();
      if (cVar12 == '\0') {
        ((void)0);
        local_c = 0x10;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x4076b7)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x005d5b00)();
        puVar22 = (undefined4*)operator_new();
        *(unsigned char*)&(uStack_1c) = 0x11;
        if (puVar22 != (undefined4*)0x0) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
          *puVar22 = 0;
        }
        uStack_1c = CONCAT31(((unsigned int)(uStack_1c) >> 8 & 0xffffff), 0x10);
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405ee3)();
        g_pGlobalUiRootController->DispatchUiSelectionToHandler(puVar22);
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
        break;
      }
    }
    if ((*(CObject**)(param_1 + 0x40) == (CObject*)0x0) ||
        (iVar35 =
             reinterpret_cast<CObject*>(*(CObject**)(param_1 + 0x40))->IsKindOf((CRuntimeClass*)0),
         iVar35 == 0)) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x401587)();
      uVar16 = 1;
    } else {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x401587)();
      uVar16 = 1;
    }
    break;
  case 0xf:
    *(uint*)(param_1 + 0xe8) = *(uint*)(param_1 + 0xe8) & ~(1 << (*(byte*)(param_2 + 7) & 0x1f));
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x402a45)();
      local_1a0 = *(uint*)(param_1 + 0xe8);
      goto LAB_00545aa0;
    }
    goto LAB_005485d8;
  case 0x10:
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
    uVar16 = 1;
    break;
  case 0x11:
    cVar12 = *(char*)(param_2 + 6);
    if (cVar12 == '\x01') {
      iVar35 = 0;
      if (param_2[7] == 0) {
        iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc);
      } else if (param_2[7] == 1) {
        iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10);
      }
      *(byte*)(param_2[8] + iVar35) =
          *(byte*)(param_2[8] + iVar35) & ~*(byte*)((int)param_2 + 0x26) |
          *(byte*)(param_2 + 9) & *(byte*)((int)param_2 + 0x26);
    } else if (cVar12 == '\x02') {
      iVar35 = 0;
      if (param_2[7] == 0) {
        iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc);
      } else if (param_2[7] == 1) {
        iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10);
      }
      *(ushort*)(param_2[8] + iVar35) =
          *(ushort*)(param_2[8] + iVar35) & ~*(ushort*)((int)param_2 + 0x26) |
          *(ushort*)(param_2 + 9) & *(ushort*)((int)param_2 + 0x26);
    } else if (cVar12 == '\x04') {
      iVar35 = 0;
      if (param_2[7] == 0) {
        iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc);
      } else if (param_2[7] == 1) {
        iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10);
      }
      *(uint*)(param_2[8] + iVar35) =
          (int)(short)(*(ushort*)(param_2 + 9) & *(ushort*)((int)param_2 + 0x26)) |
          *(uint*)(param_2[8] + iVar35) & ~(int)(short)*(ushort*)((int)param_2 + 0x26);
    }
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
      puVar22 = local_1b8;
      for (iVar35 = 10; iVar35 != 0; iVar35 = iVar35 + -1) {
        *puVar22 = *param_2;
        param_2 = param_2 + 1;
        puVar22 = puVar22 + 1;
      }
      local_1b8[1] = 0;
      local_1b8[0] = 0x11;
      local_1b8[3] = 0x28;
      local_1b8[2] = 0;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x12:
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        (*reinterpret_cast<void***>(g_pGlobalMapState))[45])();
    uVar16 = 1;
    break;
  case 0x13:
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x404007)();
    uVar16 = 1;
    break;
  case 0x14:
    g_apTerrainTypeDescriptorTable[*(short*)(param_2 + 6)]->AddToNationMetricAtField10(param_2[7]);
    uVar16 = 1;
    break;
  case 0x15:
    local_1c8.m_pchData = (char*)0x17;
    pTVar7 = g_apNationStates[*(short*)(param_2 + 6)];
    *(undefined4*)(reinterpret_cast<char*>(pTVar7) + 0x10) = param_2[7];
    puVar22 = param_2 + 0x43;
    puVar38 = (undefined4*)(reinterpret_cast<char*>(pTVar7) + 0x280);
    *(undefined4*)(reinterpret_cast<char*>(pTVar7) + 0xac) = param_2[8];
    pwVar23 = (word*)pTVar7->needTargetByType;
    pwVar20 = (word*)((int)param_2 + 0x52);
    do {
      pwVar23[-0x17] = pwVar20[-0x17];
      *pwVar23 = *pwVar20;
      pwVar23[0x17] = pwVar20[0x17];
      pwVar23[0x2e] = pwVar20[0x2e];
      pwVar23[0x45] = pwVar20[0x45];
      iVar35 = 0x10;
      puVar33 = puVar22;
      puVar39 = puVar38;
      do {
        uVar16 = *puVar33;
        puVar33 = puVar33 + 0x17;
        *puVar39 = uVar16;
        puVar39 = puVar39 + 0x17;
        iVar35 = iVar35 + -1;
      } while (iVar35 != 0);
      pwVar20 = pwVar20 + 1;
      pwVar23 = pwVar23 + 1;
      puVar38 = puVar38 + 1;
      puVar22 = puVar22 + 1;
      local_1c8.m_pchData = local_1c8.m_pchData + -1;
    } while (local_1c8.m_pchData != (char*)0x0);
    *(undefined4*)(reinterpret_cast<char*>(pTVar7) + 0x840) = param_2[0x1b3];
    *(undefined4*)(reinterpret_cast<char*>(pTVar7) + 0x844) = param_2[0x1b4];
    *(undefined4*)(reinterpret_cast<char*>(pTVar7) + 0x8f0) = param_2[0x1b5];
    (*(reinterpret_cast<char*>(pTVar7) + 0x8f4)) = *(undefined1*)(param_2 + 0x1b6);
    *(undefined4*)(reinterpret_cast<char*>(pTVar7) + 0x8f8) = param_2[0x1b7];
    (*(reinterpret_cast<char*>(pTVar7) + 0x8fc)) = *(undefined1*)(param_2 + 0x1b8);
    uVar16 = 1;
    break;
  case 0x16:
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        (*reinterpret_cast<void***>(g_apNationStates[*(short*)(param_2 + 6)]))[35])();
    uVar16 = 1;
    break;
  case 0x17:
    if (*(char*)((int)param_2 + 0x1a) == '\0') {
      reinterpret_cast<undefined4(__cdecl*)(...)>(
          (*reinterpret_cast<void***>(g_apNationStates[*(short*)(param_2 + 6)]))[124])();
      uVar16 = 1;
    } else {
      reinterpret_cast<undefined4(__cdecl*)(...)>(
          (*reinterpret_cast<void***>(g_apNationStates[*(short*)(param_2 + 6)]))[123])();
      uVar16 = 1;
    }
    break;
  case 0x18:
    ppTVar19 = g_apNationStates;
    puVar27 = (undefined2*)((int)param_2 + 0x15e);
    do {
      if (*ppTVar19 != (TGreatPower*)0x0) {
        puVar29 = (undefined2*)(reinterpret_cast<char*>((*ppTVar19)) + 0xe0);
        iVar35 = 0x17;
        puVar21 = puVar27;
        do {
          puVar29[-0x17] = puVar21[-0xa1];
          *puVar29 = *puVar21;
          puVar29[-0x66] = puVar21[0xa1];
          puVar29 = puVar29 + 1;
          iVar35 = iVar35 + -1;
          puVar21 = puVar21 + 1;
        } while (iVar35 != 0);
      }
      ppTVar19 = ppTVar19 + 1;
      puVar27 = puVar27 + 0x17;
    } while ((int)ppTVar19 < 0x6a438c);
    uVar16 = 1;
    break;
  case 0x19:
    sVar15 = *(short*)(param_2 + 7);
    sVar14 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
    if (sVar15 != sVar14) {
      pTVar7 = g_apNationStates[sVar15];
      iVar35 = 0x5c;
      pTVar7->needCapA6 = *(word*)((int)param_2 + 0x1e);
      do {
        *(undefined2*)((int)reinterpret_cast<char*>(pTVar7->city) + iVar35) =
            *(undefined2*)((int)param_2 + iVar35 + -0x3c);
        iVar35 = iVar35 + 2;
      } while (iVar35 < 0x78);
      pTVar8 = *reinterpret_cast<void***>(pTVar7);
      reinterpret_cast<undefined4(__cdecl*)(...)>(pTVar8[89])();
      local_1c4.m_pchData = (char*)(pTVar8[99]);
      iVar35 = 0;
      do {
        reinterpret_cast<undefined4(__cdecl*)(...)>(local_1c4.m_pchData)();
        iVar35 = iVar35 + 1;
      } while (iVar35 < 0x17);
      pTVar8 = *reinterpret_cast<void***>(pTVar7);
      reinterpret_cast<undefined4(__cdecl*)(...)>(pTVar8[90])();
      local_1c4.m_pchData = (char*)(pTVar8[105]);
      iVar35 = 0;
      do {
        reinterpret_cast<undefined4(__cdecl*)(...)>(local_1c4.m_pchData)();
        iVar35 = iVar35 + 1;
      } while (iVar35 < 0x11);
      reinterpret_cast<undefined4(__cdecl*)(...)>((*reinterpret_cast<void***>(pTVar7))[106])();
      puVar21 = (undefined2*)(reinterpret_cast<char*>(pTVar7) + 0xe0);
      iVar35 = 0x17;
      puVar27 = (undefined2*)((int)param_2 + 0xba);
      do {
        puVar21[-0x17] = puVar27[-0x17];
        *puVar21 = *puVar27;
        puVar21[-0x66] = puVar27[0x17];
        puVar21 = puVar21 + 1;
        iVar35 = iVar35 + -1;
        puVar27 = puVar27 + 1;
      } while (iVar35 != 0);
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x1a:
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2) {
      ppTVar19 = g_apNationStates;
      puVar27 = (undefined2*)((int)param_2 + 0x26);
      do {
        if (*ppTVar19 != (TGreatPower*)0x0) {
          *(undefined2*)(reinterpret_cast<char*>((*ppTVar19)) + 0xa2) = *puVar27;
        }
        ppTVar19 = ppTVar19 + 1;
        puVar27 = puVar27 + 1;
      } while ((int)ppTVar19 < 0x6a438c);
    }
    sVar15 = *(short*)(param_2 + 7);
    sVar14 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
    if (sVar15 != sVar14) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(
          *reinterpret_cast<void**>((*reinterpret_cast<char**>(g_pUiRuntimeContext) + 0x98)))();
      uVar16 = 1;
      break;
    }
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(
          *reinterpret_cast<void**>((*reinterpret_cast<char**>(g_pUiRuntimeContext) + 0x98)))();
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x1b:
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        (*reinterpret_cast<void***>(g_apNationStates[*(short*)(param_2 + 7)]))[108])();
    uVar16 = 1;
    break;
  case 0x1c:
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        (*reinterpret_cast<void***>(g_pNationInteractionStateManager))[24])();
    if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
      local_1c4.m_pchData = (char*)operator_new();
      local_4 = 0x14;
      if (local_1c4.m_pchData != (char*)0x0) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x404250)();
      }
      local_4 = 0xffffffff;
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x408b7f)();
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(local_1c4.m_pchData);
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x1d:
    sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
    if (*(char*)(param_2 + 7) == 'i') {
      g_apNationStates[sVar15]->CheckTransitionSlot27C(*(char*)((int)param_2 + 0x1d),
                                                       *(char*)((int)param_2 + 0x1e));
      uVar16 = 1;
    } else {
      g_apNationStates[sVar15]->PropagateWarTransitionSlot280(*(char*)((int)param_2 + 0x1d),
                                                              *(char*)((int)param_2 + 0x1e),
                                                              *(char*)((int)param_2 + 0x1f));
      uVar16 = 1;
    }
    break;
  case 0x1e:
    if (*(char*)((int)param_2 + 0x1f) == 'a') {
      if (*(char*)((int)param_2 + 0x21) == '\0') {
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_pDiplomacyTurnStateManager))[31])();
      } else if (*(char*)(param_2 + 8) == '\0') {
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_apNationStates[*(char*)(param_2 + 7)]))[161])();
      } else {
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_apNationStates[*(char*)(param_2 + 7)]))[161])();
      }
    } else if ((*(char*)((int)param_2 + 0x1f) == 'i') && (*(char*)((int)param_2 + 0x21) != '\0')) {
      cVar12 = g_pDiplomacyTurnStateManager->IsNationPairAtWar(*(char*)((int)param_2 + 0x1c),
                                                               *(char*)((int)param_2 + 0x1e));
      if (cVar12 == '\0') {
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_apNationStates[*(char*)(param_2 + 7)]))[161])();
      } else {
        pTVar6 = g_apSecondaryNationStateSlots[*(char*)((int)param_2 + 0x1d)];
        sVar15 = *(short*)(reinterpret_cast<char*>(pTVar6) + 0xe);
        if (sVar15 < 200) {
          if (sVar15 < 100) {
            sVar15 = *(short*)(reinterpret_cast<char*>(pTVar6) + 0xc);
          } else {
            sVar15 = sVar15 + -100;
          }
        } else {
          sVar15 = sVar15 + -200;
        }
        if (sVar15 != *(char*)(param_2 + 7)) {
          reinterpret_cast<undefined4(__cdecl*)(...)>((*reinterpret_cast<void***>(pTVar6))[19])();
        }
      }
    }
    pcVar25 = (char*)operator_new();
    local_4 = 0x13;
    local_1c4.m_pchData = pcVar25;
    if (pcVar25 != (char*)0x0) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
      *reinterpret_cast<void**>(pcVar25) = 0;
    }
    local_4 = 0xffffffff;
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x403f53)();
    uVar16 = 1;
    break;
  case 0x1f:
    uVar36 = param_2[6];
    if (uVar36 < 0x61636565) {
      if (uVar36 == 0x61636564) {
        sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
        iVar35 = param_2[7];
        ((void)0);
        local_4 = 0x1f;
        ((void)0);
        *(unsigned char*)&(local_4) = 0x20;
        ((void)0);
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x21);
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405245)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x40988b)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402e0f)();
        if (sVar15 == iVar35) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x407518)();
        }
        *(unsigned char*)&(local_4) = 0x20;
        ((void)0);
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x1f);
        ((void)0);
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x61626469) {
        ((void)0);
        local_4 = 0x1c;
        ((void)0);
        *(unsigned char*)&(local_4) = 0x1d;
        ((void)0);
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x1e);
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405245)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x40988b)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402e0f)();
        if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x40510f)();
        }
        *(unsigned char*)&(local_4) = 0x1d;
        ((void)0);
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x1c);
        ((void)0);
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
        break;
      }
    } else if (uVar36 < 0x64656876) {
      if (uVar36 == 0x64656875) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x40510f)();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x6367616d) {
        pcVar25 = (char*)operator_new();
        local_4 = 0x25;
        local_1c4.m_pchData = pcVar25;
        if (pcVar25 != (char*)0x0) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
          *reinterpret_cast<void**>(pcVar25) = 0;
        }
        local_4 = 0xffffffff;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405ee3)();
        g_pGlobalUiRootController->DispatchUiSelectionToHandler(pcVar25);
        ((void)0);
        uStack_1c = 0x26;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402e0f)();
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
        break;
      }
    } else if (uVar36 < 0x6c6f7366) {
      if (uVar36 == 0x6c6f7365) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_apNationStates[param_2[7]]))[171])();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x666f6666) {
        ((void)0);
        local_4 = 0x1a;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402e0f)();
        puVar22 = (undefined4*)operator_new();
        uStack_18 = 0x1b;
        if (puVar22 != (undefined4*)0x0) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x403d5f)();
          *puVar22 = 0;
        }
        uStack_18 = 0x1a;
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405ee3)();
        g_pGlobalUiRootController->DispatchUiSelectionToHandler(puVar22);
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
        break;
      }
    } else if (uVar36 < 0x6e616d66) {
      if (uVar36 == 0x6e616d65) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x409859)();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x6c6f7374) {
        uVar36 = param_2[7];
        sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
        ((unsigned char*)&(uStack_1cc))[3] = (uVar36 & 0xff) == (int)sVar15;
        ((void)0);
        local_4 = 0x22;
        ((void)0);
        *(unsigned char*)&(local_4) = 0x23;
        ((void)0);
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x24);
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x405245)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x40988b)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402e0f)();
        if ((((unsigned int)(uStack_1cc) >> 24 & 0xff) != '\0') &&
            (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2)) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x407518)();
        }
        *(unsigned char*)&(local_4) = 0x23;
        ((void)0);
        local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x22);
        ((void)0);
        local_4 = 0xffffffff;
        ((void)0);
        uVar16 = 1;
        break;
      }
    } else if (uVar36 < 0x71756975) {
      if ((uVar36 == 0x71756974) || (uVar36 == 0x6e657767)) {
        if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2) {
          ((void)0);
          local_4 = 0x16;
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x402e0f)();
          local_4 = 0xffffffff;
          ((void)0);
        }
        if ((*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2) ||
            (param_2[6] == 0x6e657767)) {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x407518)();
          uVar16 = 1;
        } else {
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x4077e3)();
          uVar16 = 1;
        }
        break;
      }
    } else if (uVar36 < 0x72657070) {
      if (uVar36 == 0x7265706f) {
        uVar36 = param_2[7] & 7;
        if (((g_apNationStates[uVar36] == (TGreatPower*)0x0) &&
             (iVar35 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)(),
              param_2[1] == iVar35)) &&
            (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1)) {
          bVar10 = true;
        } else {
          bVar10 = false;
        }
        if ((uVar36 < 7) &&
            ((bVar10 || ((g_apNationStates[uVar36] != (TGreatPower*)0x0 &&
                          ((iVar35 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)(),
                            param_2[1] == iVar35 ||
                                (cVar12 = reinterpret_cast<undefined4(__cdecl*)(...)>(
                                     (*reinterpret_cast<void***>(g_apNationStates[uVar36]))[40])(),
                                 cVar12 != '\0')))))))) {
          uVar16 = param_2[1];
          /* WARNING: Load size is inaccurate */
          local_1c4.m_pchData = (char*)(int)local_1d0.m_pchData[uVar36 * 4 + 0x94];
          pcVar25 = *(char**)(local_1d0.m_pchData + uVar36 * 4 + 0x78);
          local_1d0.m_pchData = local_1d0.m_pchData + uVar36 * 4 + 0x78;
          local_1b8[4] = 0x74696d65;
          local_1a4[0] = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
          uVar30 = 0xffffffff;
          do {
            pcVar17 = pcVar25;
            if (uVar30 == 0)
              break;
            uVar30 = uVar30 - 1;
            pcVar17 = pcVar25 + 1;
            cVar12 = *pcVar25;
            pcVar25 = pcVar17;
          } while (cVar12 != '\0');
          local_1b8[1] = 0;
          local_1b8[0] = 9;
          uVar30 = ~uVar30;
          local_1b8[2] = 0;
          local_1b8[3] = 100;
          local_1a0 = CONCAT31(((unsigned int)(local_1a0) >> 8 & 0xffffff), (sbyte)uVar36);
          pcVar25 = pcVar17 + -uVar30;
          pcVar17 = local_198;
          for (uVar31 = uVar30 >> 2; uVar31 != 0; uVar31 = uVar31 - 1) {
            *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
            pcVar25 = pcVar25 + 4;
            pcVar17 = pcVar17 + 4;
          }
          for (uVar30 = uVar30 & 3; uVar30 != 0; uVar30 = uVar30 - 1) {
            *pcVar17 = *pcVar25;
            pcVar25 = pcVar25 + 1;
            pcVar17 = pcVar17 + 1;
          }
          uVar30 = 0xffffffff;
          CVar42.m_pchData = local_1c4.m_pchData;
          do {
            pcVar25 = CVar42.m_pchData;
            if (uVar30 == 0)
              break;
            uVar30 = uVar30 - 1;
            pcVar25 = CVar42.m_pchData + 1;
            cVar12 = *CVar42.m_pchData;
            CVar42.m_pchData = pcVar25;
          } while (cVar12 != '\0');
          uVar30 = ~uVar30;
          pcVar25 = pcVar25 + -uVar30;
          pcVar17 = local_177;
          for (uVar31 = uVar30 >> 2; uVar31 != 0; uVar31 = uVar31 - 1) {
            *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
            pcVar25 = pcVar25 + 4;
            pcVar17 = pcVar17 + 4;
          }
          for (uVar30 = uVar30 & 3; uVar30 != 0; uVar30 = uVar30 - 1) {
            *pcVar17 = *pcVar25;
            pcVar25 = pcVar25 + 1;
            pcVar17 = pcVar17 + 1;
          }
          local_19c = uVar16;
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
          ((void)0);
          local_c = 0x17;
          ((void)0);
          local_c = CONCAT31(((unsigned int)(local_c) >> 8 & 0xffffff), 0x18);
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e7e)();
          (reinterpret_cast<GhStr*>(&local_1d0)->m_pchData = (char*)(unaff_EDI));
          uStack_18 = 0x19;
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x40988b)();
          uStack_12c = 0x74696d65;
          uVar13 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
          uStack_138 = 0;
          local_128 = CONCAT31(((unsigned int)(local_128) >> 8 & 0xffffff), uVar13);
          uStack_134 = 0;
          uStack_13c = 0xc;
          uStack_130 = 0x11c;
          cStack_24 = 0xff;
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
          uVar30 = 0xffffffff;
          do {
            pcVar25 = unaff_EBP;
            if (uVar30 == 0)
              break;
            uVar30 = uVar30 - 1;
            pcVar25 = unaff_EBP + 1;
            cVar12 = *unaff_EBP;
            unaff_EBP = pcVar25;
          } while (cVar12 != '\0');
          uVar30 = ~uVar30;
          pcVar25 = pcVar25 + -uVar30;
          pcVar17 = local_124;
          for (uVar31 = uVar30 >> 2; uVar31 != 0; uVar31 = uVar31 - 1) {
            *(undefined4*)pcVar17 = *(undefined4*)pcVar25;
            pcVar25 = pcVar25 + 4;
            pcVar17 = pcVar17 + 4;
          }
          for (uVar30 = uVar30 & 3; uVar30 != 0; uVar30 = uVar30 - 1) {
            *pcVar17 = *pcVar25;
            pcVar25 = pcVar25 + 1;
            pcVar17 = pcVar17 + 1;
          }
          uStack_13c = 0xc;
          uStack_23 = 0xff;
          uStack_134 = 0;
          cStack_24 = -1 - ('\x01' << (sbyte)uVar36);
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
          *(unsigned char*)&(local_4) = 0x18;
          ((void)0);
          local_4 = CONCAT31(((unsigned int)(local_4) >> 8 & 0xffffff), 0x17);
          ((void)0);
          local_4 = 0xffffffff;
          ((void)0);
          uVar16 = 1;
        } else {
          local_1b8[4] = 0x74696d65;
          local_1a4[0] = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
          local_1b8[2] = param_2[1];
          local_1b8[1] = 0;
          local_1b8[0] = 0x1f;
          local_1b8[3] = 0x20;
          local_1a0 = 0x666f6666;
          local_19c = 0x29;
          reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
          uVar16 = 1;
        }
        break;
      }
      if ((uVar36 == 0x72656765) &&
          (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 2)) {
        g_pStrategicMapViewSystem->RebuildNationClipRegionsAndDispatchMapEvent();
        uVar16 = 1;
        break;
      }
    } else {
      if (uVar36 == 0x73617665) {
        param_1[0xf4] = *(code*)(param_2 + 7);
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x407559)();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x74726164) {
        sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_apNationStates[sVar15]))[18])();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x74726173) {
        sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
        reinterpret_cast<undefined4(__cdecl*)(...)>(
            (*reinterpret_cast<void***>(g_apNationStates[sVar15]))[52])();
        uVar16 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0x20:
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x0055c9f0)(
        (TCountry*)g_pInterNationEventQueueManager, (int)*(short*)(param_2 + 6),
        (int)*(char*)((int)param_2 + 0x1a), (int)*(char*)((int)param_2 + 0x1b), '\x01');
    uVar16 = 1;
    break;
  case 0x21:
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x403175)();
    uVar16 = 1;
    break;
  case 0x22:
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x401474)();
    uVar16 = 1;
    break;
  case 0x23:
    sVar15 = *(short*)(param_2 + 7);
    iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc);
    *(undefined1*)(iVar35 + 4 + sVar15 * 0x24) = *(undefined1*)(param_2 + 9);
    iVar35 = iVar35 + sVar15 * 0x24;
    *(undefined1*)(iVar35 + 5) = *(undefined1*)((int)param_2 + 0x25);
    *(undefined1*)(iVar35 + 6) = *(undefined1*)((int)param_2 + 0x26);
    *(undefined1*)(iVar35 + 0xc) = *(undefined1*)(param_2 + 0xb);
    *(byte*)(iVar35 + 0xd) = *(byte*)(iVar35 + 0xd) | *(byte*)((int)param_2 + 0x2d);
    *(undefined1*)(iVar35 + 0x18) = *(undefined1*)(param_2 + 0xe);
    *(undefined2*)(iVar35 + 0x1c) = *(undefined2*)(param_2 + 0xf);
    uVar16 = 1;
    break;
  case 0x24:
    sVar15 = *(short*)(param_2 + 7);
    iVar34 = 10;
    iVar35 = *(int*)(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10);
    *(undefined1*)(iVar35 + sVar15 * 0xa8) = *(undefined1*)(param_2 + 8);
    iVar35 = iVar35 + sVar15 * 0xa8;
    *(undefined1*)(iVar35 + 2) = *(undefined1*)((int)param_2 + 0x22);
    *(undefined1*)(iVar35 + 3) = *(undefined1*)((int)param_2 + 0x23);
    *(undefined2*)(iVar35 + 6) = *(undefined2*)((int)param_2 + 0x26);
    puVar27 = (undefined2*)(iVar35 + 0x82);
    puVar21 = (undefined2*)((int)param_2 + 0xa2);
    do {
      uVar4 = *puVar21;
      puVar21 = puVar21 + 1;
      *puVar27 = uVar4;
      puVar27 = puVar27 + 1;
      iVar34 = iVar34 + -1;
    } while (iVar34 != 0);
    *(undefined1*)(iVar35 + 0xa1) = *(undefined1*)((int)param_2 + 0xc1);
    *(undefined1*)(iVar35 + 0xa2) = *(undefined1*)((int)param_2 + 0xc2);
    uVar16 = 1;
    break;
  case 0x25:
    iVar35 = 0;
    piVar24 = (int*)(param_2 + 6);
    local_1d4.m_pchData = (char*)0x0;
    pcVar32 = param_1 + 0xbc;
    iVar34 = 7;
    do {
      if (*piVar24 != 0x756e6b6e) {
        *(int*)pcVar32 = *piVar24;
      }
      if (*(int*)pcVar32 == 0x72656479) {
        iVar35 = iVar35 + 1;
      } else if (*(int*)pcVar32 == 0x62757379) {
        local_1d4.m_pchData = local_1d4.m_pchData + 1;
      }
      piVar24 = piVar24 + 1;
      pcVar32 = pcVar32 + 4;
      iVar34 = iVar34 + -1;
    } while (iVar34 != 0);
    if ((0 < iVar35) && (local_1d4.m_pchData == (char*)0x1)) {
      sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
      iVar35 = (int)sVar15;
      if (iVar35 == -1) {
        iVar34 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a3d)();
        iVar35 = 0;
        piVar24 = (int*)((int)g_pGameFlowState + 0x48);
        do {
          if (*piVar24 == iVar34)
            goto LAB_0054833b;
          iVar35 = iVar35 + 1;
          piVar24 = piVar24 + 1;
        } while (iVar35 < 7);
        iVar35 = -1;
      }
    LAB_0054833b:
      if ((*(int*)(param_1 + iVar35 * 4 + 0xbc) == 0x62757379) &&
          (param_1[0xf4] != (CObject_slot_0x04_0x04)0x0)) {
        g_pSfxPlaybackSystem->PlaySoundEffect(0x13f2, 0, 1);
        uVar16 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0x26:
    puVar22 = param_2 + 6;
    pTVar43 = g_pDiplomacyTurnStateManager;
    for (iVar35 = 0xc0;
         pTVar43 = (TDiplomacyMgr*)(reinterpret_cast<char*>(pTVar43) + 0x4), iVar35 != 0;
         iVar35 = iVar35 + -1) {
      *(undefined4*)pTVar43 = *puVar22;
      puVar22 = puVar22 + 1;
    }
    puVar22 = param_2 + 0xc6;
    puVar38 = (undefined4*)(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) + 0x304);
    for (iVar35 = 0x60; iVar35 != 0; iVar35 = iVar35 + -1) {
      *puVar38 = *puVar22;
      puVar22 = puVar22 + 1;
      puVar38 = puVar38 + 1;
    }
    puVar22 = param_2 + 0x126;
    puVar38 = (undefined4*)(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) + 0x484);
    for (iVar35 = 0xc0; iVar35 != 0; iVar35 = iVar35 + -1) {
      *puVar38 = *puVar22;
      puVar22 = puVar22 + 1;
      puVar38 = puVar38 + 1;
    }
    *(undefined4*)(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) + 0x784) = param_2[0x1e6];
    pTVar43 = g_pDiplomacyTurnStateManager;
    *(undefined4*)(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) + 0x788) = param_2[0x1e7];
    *(undefined2*)(reinterpret_cast<char*>(pTVar43) + 0x78c) = *(undefined2*)(param_2 + 0x1e8);
    uVar16 = 1;
    puVar22 = param_2 + 0x1e9;
    puVar38 = (undefined4*)(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) + 0x1824);
    for (iVar35 = 0x1c; iVar35 != 0; iVar35 = iVar35 + -1) {
      *puVar38 = *puVar22;
      puVar22 = puVar22 + 1;
      puVar38 = puVar38 + 1;
    }
    break;
  case 0x27:
    g_apTerrainTypeDescriptorTable[param_2[6]]->ApplyJoinEmpireModeForTargetNation(param_2[7],
                                                                                   param_2[8]);
    uVar16 = 1;
    break;
  case 0x28:
  case 0x2e:
  case 0x2f:
  case 0x30:
  case 0x31:
  case 0x32:
    g_nSaveFormatVersion = 0x6e657458;
    hMem = GlobalAlloc(2, param_2[3]);
    GlobalLock(hMem);
    ((void)0); // Ghidra _memmove() with register-folded args; body-only side effect
    GlobalUnlock(hMem);
    local_1c4.m_pchData = (char*)operator_new();
    local_4 = 0x15;
    if (local_1c4.m_pchData == (char*)0x0) {
      piVar24 = (int*)0x0;
    } else {
      piVar24 = (int*)reinterpret_cast<undefined4(__cdecl*)(...)>(0x401e1a)();
    }
    local_4 = 0xffffffff;
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x408765)();
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x403170)();
    reinterpret_cast<undefined4(__cdecl*)(...)>(*reinterpret_cast<void**>((*piVar24 + 0x1c)))();
    g_nSaveFormatVersion = -1;
    uVar16 = 1;
    break;
  case 0x29:
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        *reinterpret_cast<void**>((*(*reinterpret_cast<int**>(0x006a475c)) + 0xc)))();
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x406b27)();
    uVar36 = param_2[6];
    if (uVar36 < 0x64696768) {
      if (uVar36 == 0x64696767) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x4052e0)();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x6465706c) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x4015dc)();
        uVar16 = 1;
        break;
      }
    } else if (uVar36 < 0x6d6f7666) {
      if (uVar36 == 0x6d6f7665) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x403134)();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x6d696e65) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402dfb)();
        uVar16 = 1;
        break;
      }
    } else {
      if (uVar36 == 0x72616c79) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x4065af)();
        uVar16 = 1;
        break;
      }
      if (uVar36 == 0x73656c65) {
        reinterpret_cast<undefined4(__cdecl*)(...)>(0x402cca)();
        uVar16 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0x2a:
    reinterpret_cast<undefined4(__cdecl*)(...)>(
        *reinterpret_cast<void**>((*(*reinterpret_cast<int**>(0x006a475c)) + 0xc)))();
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x406b27)();
    reinterpret_cast<undefined4(__cdecl*)(...)>(0x406b27)();
    if (param_2[6] == 0x66697265) {
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x402770)();
      uVar16 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x2b:
    (*reinterpret_cast<int*>(0x006a3d64)) =
        (*reinterpret_cast<int*>(0x006a3d64)) | (int)*(char*)((int)param_2 + 0x19);
    if (*(char*)(param_2 + 6) != '\0') {
      local_1b8[4] = 0x74696d65;
      local_1a4[0] = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
      local_1b8[0] = 0x2b;
      local_1b8[1] = 0;
      local_1b8[2] = 0;
      local_1a0 = local_1a0 & 0xffffff00;
      local_1b8[3] = 0x1c;
      uVar13 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
      local_1b8[2] = param_2[1];
      *reinterpret_cast<unsigned short*>(&(local_1a0)) = CONCAT11(uVar13, (undefined1)local_1a0);
      reinterpret_cast<undefined4(__cdecl*)(...)>(0x405a5b)();
    }
    goto LAB_005485d8;
  case 0x2c:
    iVar35 = (int)*(short*)(param_2 + 7);
    sVar15 = reinterpret_cast<undefined4(__cdecl*)(...)>(0x403b16)();
    if (iVar35 != sVar15) {
      *(undefined4*)(reinterpret_cast<char*>(g_apNationStates[iVar35]) + 0x910) = param_2[8];
      *(undefined4*)(reinterpret_cast<char*>(g_apNationStates[iVar35]) + 0x914) = param_2[9];
      if (g_apNationStates[iVar35] == (TGreatPower*)0x0) {
        pTVar41 = (TCity*)0x0;
      } else {
        pTVar41 = g_apNationStates[iVar35]->city;
      }
      puVar27 = (undefined2*)(reinterpret_cast<char*>(pTVar41) + 0xe);
      puVar21 = (undefined2*)((int)param_2 + 0x2e);
      iVar34 = 0x1e;
      do {
        uVar4 = *puVar21;
        puVar21 = puVar21 + 1;
        *puVar27 = uVar4;
        puVar27 = puVar27 + 1;
        iVar34 = iVar34 + -1;
      } while (iVar34 != 0);
      puVar27 = (undefined2*)(reinterpret_cast<char*>(pTVar41) + 0x4a);
      puVar21 = (undefined2*)((int)param_2 + 0x6a);
      iVar34 = 9;
      do {
        uVar4 = *puVar21;
        puVar21 = puVar21 + 1;
        *puVar27 = uVar4;
        puVar27 = puVar27 + 1;
        iVar34 = iVar34 + -1;
      } while (iVar34 != 0);
      puVar27 = (undefined2*)(reinterpret_cast<char*>(pTVar41) + 0x5c);
      puVar22 = param_2 + 0x1f;
      iVar34 = 0xe;
      do {
        uVar4 = *(undefined2*)puVar22;
        puVar22 = (undefined4*)((int)puVar22 + 2);
        *puVar27 = uVar4;
        puVar27 = puVar27 + 1;
        iVar34 = iVar34 + -1;
      } while (iVar34 != 0);
      reinterpret_cast<undefined4(__cdecl*)(...)>(
          (*reinterpret_cast<void***>(g_apNationStates[iVar35]))[89])();
      pwVar20 = reinterpret_cast<word*>(reinterpret_cast<char*>(pTVar41) + 0xB6);
      *(undefined4*)(reinterpret_cast<char*>(pTVar41) + 0x78) = param_2[0x26];
      *(undefined2*)(reinterpret_cast<char*>(pTVar41) + 0xb4) = *(undefined2*)(param_2 + 0x27);
      pwVar23 = (word*)((int)param_2 + 0x9e);
      iVar35 = 0x17;
      pwVar26 = pwVar20;
      do {
        wVar3 = *pwVar23;
        pwVar23 = pwVar23 + 1;
        *pwVar26 = wVar3;
        pwVar26 = pwVar26 + 1;
        iVar35 = iVar35 + -1;
      } while (iVar35 != 0);
      puVar27 = (undefined2*)(reinterpret_cast<char*>(pTVar41) + 0x1dc);
      puVar22 = param_2 + 0x33;
      iVar35 = 0x10;
      do {
        uVar4 = *(undefined2*)puVar22;
        puVar22 = (undefined4*)((int)puVar22 + 2);
        *puVar27 = uVar4;
        puVar27 = puVar27 + 1;
        iVar35 = iVar35 + -1;
      } while (iVar35 != 0);
      puVar27 = (undefined2*)(reinterpret_cast<char*>(pTVar41) + 0x1fc);
      puVar22 = param_2 + 0x3b;
      iVar35 = 0x10;
      do {
        uVar4 = *(undefined2*)puVar22;
        puVar22 = (undefined4*)((int)puVar22 + 2);
        *puVar27 = uVar4;
        puVar27 = puVar27 + 1;
        iVar35 = iVar35 + -1;
      } while (iVar35 != 0);
      *(undefined2*)(reinterpret_cast<char*>(pTVar41) + 0x26c) = *(undefined2*)(param_2 + 0x43);
      pwVar23 = (word*)((int)param_2 + 0x9e);
      iVar35 = 0x17;
      do {
        wVar3 = *pwVar23;
        pwVar23 = pwVar23 + 1;
        *pwVar20 = wVar3;
        pwVar20 = pwVar20 + 1;
        iVar35 = iVar35 + -1;
      } while (iVar35 != 0);
      ppvVar28 = pTVar41->orderSlotsE4;
      puVar22 = param_2 + 0x44;
      iVar35 = 0x17;
      do {
        if (*ppvVar28 != (void*)0x0) {
          *(undefined4*)((int)*ppvVar28 + 0x44) = *puVar22;
        }
        puVar22 = puVar22 + 1;
        ppvVar28 = ppvVar28 + 1;
        iVar35 = iVar35 + -1;
      } while (iVar35 != 0);
      iVar35 = *(int*)(reinterpret_cast<char*>(pTVar41) + 0x1d8);
      *(undefined2*)(iVar35 + 8) = *(undefined2*)(param_2 + 0x5b);
      *(undefined4*)(iVar35 + 0xc) = param_2[0x5c];
      *(undefined2*)(iVar35 + 0x1c) = *(undefined2*)(param_2 + 0x5d);
      *(undefined2*)(iVar35 + 0x1e) = *(undefined2*)((int)param_2 + 0x176);
      *(undefined2*)(iVar35 + 0x20) = *(undefined2*)(param_2 + 0x5e);
      *(undefined2*)(*(int*)(iVar35 + 0x10) + 4) = *(undefined2*)((int)param_2 + 0x17a);
      *(undefined2*)(*(int*)(iVar35 + 0x10) + 6) = *(undefined2*)(param_2 + 0x5f);
      *(undefined2*)(*(int*)(iVar35 + 0x10) + 8) = *(undefined2*)((int)param_2 + 0x17e);
      *(undefined2*)(*(int*)(iVar35 + 0x14) + 4) = *(undefined2*)(param_2 + 0x60);
      *(undefined2*)(*(int*)(iVar35 + 0x14) + 6) = *(undefined2*)((int)param_2 + 0x182);
      *(undefined2*)(*(int*)(iVar35 + 0x14) + 8) = *(undefined2*)(param_2 + 0x61);
      *(undefined2*)(*(int*)(iVar35 + 0x18) + 4) = *(undefined2*)((int)param_2 + 0x186);
      *(undefined2*)(*(int*)(iVar35 + 0x18) + 6) = *(undefined2*)(param_2 + 0x62);
      *(undefined2*)(*(int*)(iVar35 + 0x18) + 8) = *(undefined2*)((int)param_2 + 0x18a);
      uVar16 = 1;
      break;
    }
  LAB_005485d8:
    uVar16 = 1;
    break;
  case 0x2d:
    iVar35 = 0x17;
    puVar27 = (undefined2*)(reinterpret_cast<char*>(
                                g_apSecondaryNationStateSlots[*(short*)(param_2 + 7)]) +
                            0x14);
    puVar21 = (undefined2*)((int)param_2 + 0x1e);
    do {
      uVar4 = *puVar21;
      puVar21 = puVar21 + 1;
      *puVar27 = uVar4;
      puVar27 = puVar27 + 1;
      iVar35 = iVar35 + -1;
    } while (iVar35 != 0);
    uVar16 = 1;
  }
  *unaff_FS_OFFSET = local_c;
  return uVar16;
}

// FUNCTION: IMPERIALISM 0x005494b0
void TMultiplayerMgr::CreateAndSendTurnEvent12_TwoShorts(short shortA, short shortB) {
  TurnEvent12Packet packet;
  packet.eventCode = 0x12;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.shortA = shortA;
  packet.shortB = shortB;
  g_pNetMgr006a6014->Send(&packet, 0);
}

struct TurnEvent13Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short nationSlot;
  int payloadDwords[9];
  unsigned char pad3C[4]; // original frame/messageLength is 0x40
};

// FUNCTION: IMPERIALISM 0x00549540
void TMultiplayerMgr::CreateAndSendTurnEvent13_NationAndNineDwords(int nationSlot,
                                                                   int* payloadDwords) {
  TurnEvent13Packet packet;
  packet.eventCode = 0x13;
  packet.fromNetworkId = 0;
  packet.toNetworkId = g_pGameFlowState->nationSessionIds[nationSlot];
  packet.messageLength = 0x40;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.nationSlot = static_cast<short>(nationSlot);
  for (int dwordIndex = 0; dwordIndex < 9; ++dwordIndex) {
    packet.payloadDwords[dwordIndex] = payloadDwords[dwordIndex];
  }
  g_pNetMgr006a6014->Send(&packet, 0);
}

struct TurnEvent20Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  short eventParam18;
  unsigned char byteA;
  unsigned char byteB;
};

// FUNCTION: IMPERIALISM 0x005495e0
void TMultiplayerMgr::CreateAndSendTurnEvent20_ShortAndTwoBytes(short eventParam,
                                                                unsigned char byteA,
                                                                unsigned char byteB) {
  TurnEvent20Packet packet;
  packet.eventCode = 0x20;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventParam18 = eventParam;
  packet.byteA = byteA;
  packet.byteB = byteB;
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent21Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char byte0;
  unsigned char byte1;
  unsigned char byte2;
  unsigned char pad18[4]; // original frame/messageLength is 0x1c
};

// FUNCTION: IMPERIALISM 0x00549680
void TMultiplayerMgr::CreateAndSendTurnEvent21_ThreeBytes(unsigned char byte0, unsigned char byte1,
                                                          unsigned char byte2) {
  TurnEvent21Packet packet;
  packet.eventCode = 0x21;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.byte0 = byte0;
  packet.byte1 = byte1;
  packet.byte2 = byte2;
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent22Packet : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  unsigned char byteVal;
  unsigned char pad19;
  short shortVal;
};

// FUNCTION: IMPERIALISM 0x00549720
void TMultiplayerMgr::CreateAndSendTurnEvent22_ByteAndShort(unsigned char byteVal, short shortVal) {
  TurnEvent22Packet packet;
  packet.eventCode = 0x22;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x1c;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.byteVal = byteVal;
  packet.shortVal = shortVal;
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TurnEvent1APacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short uiTurnToken;
  short field18;
  short field1a;
  short field1c;
  short field1e;
  short field20;
  short field22;
  short nationCapabilityFlags[7];
};

// FUNCTION: IMPERIALISM 0x005497b0
void TMultiplayerMgr::DispatchTurnEvent1AWithNationActionPayload(short param0, short param1,
                                                                 short param2, short param3,
                                                                 short param4) {
  TurnEvent1APacket packet;
  packet.eventCode = 0x1a;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x34;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.field18 = param0;
  packet.field1a = 0;
  packet.field1c = param1;
  packet.field1e = param2;
  packet.field20 = param3;
  packet.field22 = param4;
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    TGreatPower* nationState = g_apNationStates[nationIndex];
    if (nationState != 0) {
      packet.nationCapabilityFlags[nationIndex] =
          nationState->ReturnFalseNationStateCapabilityFlag90(0);
    } else {
      packet.nationCapabilityFlags[nationIndex] = 0;
    }
  }
  g_pNetMgr006a6014->Send(&packet, 1);
}

struct TaggedGameStateTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  int resolvedNationId;
  int tagParam;
  int valueParam;
};

// FUNCTION: IMPERIALISM 0x0054a340
void TMultiplayerMgr::DispatchTaggedGameStateEvent1F20(int packetTag, int param2,
                                                       int nationSlotOrMode) {
  TaggedGameStateTurnEventPacket packet;
  packet.eventCode = 0x1f;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x20;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.tagParam = packetTag;
  packet.valueParam = param2;
  if ((nationSlotOrMode == -2) || (nationSlotOrMode == -3)) {
    packet.resolvedNationId = 0;
  } else if (nationSlotOrMode == -1) {
    packet.resolvedNationId = -1;
  } else {
    packet.resolvedNationId = g_pGameFlowState->nationSessionIds[nationSlotOrMode];
  }
  g_pNetMgr006a6014->Send(&packet, nationSlotOrMode == -3 ? 1 : 0);
}

#pragma pack(push, 1)
struct CityRedrawInvalidateTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short uiTurnToken;
  short cityId;
  unsigned char cityHeader00[4];
  short cityWord04;
  short cityWord06;
  unsigned char cityByte08;
  short adjacentRegionIds0A[12];
  short adjacentRegionIds22[12];
  unsigned char cityBytes3A[3];
  short cityWord3E;
  short cityWord40;
  short linkedRegionIds42[32];
  short linkedRegionIds82[10];
  TMilitaryUnit* stationedUnitChain98;
  int cityScoreValue9C;
  unsigned char cityBytesA0[4];
  CString cityNameA4;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TileRedrawInvalidateTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15;
  short uiTurnToken;
  short tileIndex;
  TTerrainStateRecordView tileSnapshot;
};
#pragma pack(pop)

// FUNCTION: IMPERIALISM 0x0054ab20
extern "C" void __stdcall DispatchTileRedrawInvalidateEvent(short tileIndex) {
  TileRedrawInvalidateTurnEventPacket packet;
  packet.eventCode = 0x23;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0x44;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.tileIndex = tileIndex;
  packet.tileSnapshot = g_pGlobalMapState->terrainStateTable[tileIndex];

  g_pNetMgr006a6014->Send(&packet, 0);
}

struct TJoinEmpireTurnEventPacket : NetMessage {
  int packetTag;
  unsigned char activeNationId;
  unsigned char pad15[3];
  int sourceNationSlot;
  int targetNationSlot;
  int modeValue;
};

// FUNCTION: IMPERIALISM 0x0054abf0
void TMultiplayerMgr::DispatchCityRedrawInvalidateEvent(short cityId) {
  CityRedrawInvalidateTurnEventPacket packet;
  packet.eventCode = 0x24;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 200;
  packet.packetTag = 0x74696d65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.uiTurnToken = static_cast<short>(g_pGameFlowState->pendingNationSlotIndex);
  packet.cityId = cityId;

  const TGlobalMapCityScoreRecord* src = &g_pGlobalMapState->cityScoreTable[cityId];
  packet.cityHeader00[0] = src->ownerNationCode00;
  packet.cityHeader00[1] = src->byte01;
  packet.cityHeader00[2] = src->developmentStage;
  packet.cityHeader00[3] = src->fortLevel03;
  packet.cityWord04 = src->ownerNationSlot;
  packet.cityWord06 = src->lastTurnTick;
  packet.cityByte08 = src->adjacentRegionCount08;

  for (int wordIndex = 0; wordIndex < 12; ++wordIndex) {
    packet.adjacentRegionIds0A[wordIndex] = src->adjacentRegionIds0A[wordIndex];
    packet.adjacentRegionIds22[wordIndex] = src->adjacentRegionIds0A[wordIndex + 12];
  }

  packet.cityBytes3A[0] = src->linkedRegionCount;
  packet.cityBytes3A[1] = src->byte3B;
  packet.cityBytes3A[2] = src->byte3C;
  packet.cityWord3E = src->secondaryNeighborTileIndex3e;
  packet.cityWord40 = src->primaryNeighborTileIndex40;

  for (int linkedIndex = 0; linkedIndex < 32; ++linkedIndex) {
    packet.linkedRegionIds42[linkedIndex] = src->linkedRegionIds[linkedIndex];
  }
  packet.linkedRegionIds82[0] = src->linkedRegionIds[32];
  packet.linkedRegionIds82[1] = src->stage1CounterA;
  packet.linkedRegionIds82[2] = src->stage1CounterB;
  packet.linkedRegionIds82[3] = src->pad88;
  packet.linkedRegionIds82[4] = src->stage1CounterC;
  packet.linkedRegionIds82[5] = src->stage1CounterD;
  packet.linkedRegionIds82[6] = src->stage2CounterA;
  packet.linkedRegionIds82[7] = src->stage2CounterB;
  packet.linkedRegionIds82[8] = src->stage2CounterC;
  packet.linkedRegionIds82[9] = src->field94;

  packet.stationedUnitChain98 = src->stationedUnitChain98;
  packet.cityScoreValue9C = src->cityScoreValue;
  packet.cityBytesA0[0] = src->padA0;
  packet.cityBytesA0[1] = src->exploredByNationMaskA1;
  packet.cityBytesA0[2] = src->padA2;
  packet.cityBytesA0[3] = src->regionClassA3;
  packet.cityNameA4 = src->cityNameA4;

  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054c5a0
void TMultiplayerMgr::DispatchJoinEmpireModeEventPacket24_27(int sourceNation, int targetNation,
                                                             int mode) {
  TJoinEmpireTurnEventPacket packet;
  packet.packetTag = 0x74696D65;
  packet.activeNationId = static_cast<unsigned char>(g_pSimMgr->GetActiveNationId());
  packet.eventCode = 0;
  packet.fromNetworkId = 0;
  packet.toNetworkId = 0;
  packet.messageLength = 0;
  packet.sourceNationSlot = sourceNation;
  packet.targetNationSlot = targetNation;
  packet.modeValue = mode;
  packet.messageLength = 0x24;
  packet.eventCode = 0x27;
  g_pNetMgr006a6014->Send(&packet, 0);
}

// FUNCTION: IMPERIALISM 0x0054c660
void TMultiplayerMgr::NoOpCallbackRet4(void* param) {
  (void)param;
}

// Trivial credential-init stub reused across the networking cluster (0x5e34b0):
// unconditionally reports success regardless of receiver.
// FUNCTION: IMPERIALISM 0x005e34b0
static char ReturnTrueRuntimeCredentialInitStub() {
  return 1;
}
