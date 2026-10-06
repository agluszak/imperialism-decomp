#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668588
class TTransportPicture : public TPicture {
public:
  short gaugeMetricId;
  short resourceMetricSlot;
  short splitValue94;
  short splitValue96;
  short splitLimit;

  TTransportPicture();
  virtual ~TTransportPicture() override;
  DECLARE_DYNCREATE(TTransportPicture)
  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void Draw(RECT* rectBuffer) override;
  virtual void Refresh();
};

ASSERT_SIZE(TTransportPicture, 0x9c);
