#pragma once

#include "compat.h"
#include "game/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668588
class TTransportPicture : public TPicture {
public:
  short gaugeMetricId90;
  short resourceMetricSlot92;
  short splitValue94;
  short splitValue96;
  short splitLimit98;

  TTransportPicture();
  virtual ~TTransportPicture() override;
  DECLARE_DYNCREATE(TTransportPicture)
  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual void Refresh();
};

ASSERT_SIZE(TTransportPicture, 0x9c);
