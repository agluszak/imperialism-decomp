#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TUberCluster.h"

struct CRuntimeClass;
struct PanelEventPayload;

// VTABLE: IMPERIALISM 0x6653c8
class TProductionCluster : public TUberCluster {
public:
  int field88;
  short field8c;
  short field8e;
  int field90;
  int field94;

  TProductionCluster();
  virtual ~TProductionCluster() override;
  CRuntimeClass* GetRuntimeClass() const override;

  virtual void ApplyMoveValue(int value) override;
  virtual int NotifyControlSelectionChange(void* boundEntry, int arg2 = 0) override;
  virtual int GetControlFlag(int value90 = 0, int value94 = 0) override;
  void HandleValuePanelSplitArrowCommand(int commandId, void* eventArg, int eventExtra);
};

ASSERT_SIZE(TProductionCluster, 0x98);

TProductionCluster* __cdecl CreateTProductionClusterInstance(void);
TProductionCluster* ConstructTProductionClusterBaseState(TProductionCluster* cluster);
TProductionCluster* DestructTProductionClusterAndMaybeFree(TProductionCluster* cluster,
                                                           unsigned char freeSelfFlag);
void HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward(TProductionCluster* cluster,
                                                                        int commandId,
                                                                        void* eventArg,
                                                                        int eventExtra);
