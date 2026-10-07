#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x64b0c0
class TCluster : public TControl {
public:
  DECLARE_DYNCREATE(TCluster)
  virtual ~TCluster() override;
  virtual TObject* ShallowClone() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual int GetCurrentChoice();
  virtual void SetCurrentChoice(int childTag);
  int selectedChildTag;

  TCluster();
  TCluster(const TCluster& source);

  void InitializeClusterFrameAndAttachToParent(TView* parent, POINT* offset, POINT* size,
                                               int layoutParam4, int layoutParam5, int layoutParam6,
                                               int layoutParam7);
};
ASSERT_SIZE(TCluster, 0x88);
