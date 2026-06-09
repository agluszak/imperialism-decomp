#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TUberCluster.h"

struct PanelEventPayload;
enum EArrowSplitCommandId;

// VTABLE: IMPERIALISM 0x6653c8
class TProductionCluster : public TUberCluster {
public:
  int field88;
  short field8c;
  short field8e;
  int field90;
  int field94;

  TProductionCluster();
  virtual ~TProductionCluster();

  virtual void ApplyMoveValue(int value);
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0);
  virtual int GetControlFlag(int value90 = 0, int value94 = 0);
  void HandleValuePanelSplitArrowCommand(int commandId, void* eventArg, int eventExtra);
};

ASSERT_SIZE(TProductionCluster, 0x98);

TProductionCluster* __cdecl CreateTProductionClusterInstance(void);
void* __cdecl GetTProductionClusterClassNamePointer(void);
TProductionCluster* ConstructTProductionClusterBaseState(TProductionCluster* cluster);
TProductionCluster* DestructTProductionClusterAndMaybeFree(TProductionCluster* cluster,
                                                           unsigned char freeSelfFlag);
void HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward(TProductionCluster* cluster,
                                                                        int commandId,
                                                                        void* eventArg,
                                                                        int eventExtra);
