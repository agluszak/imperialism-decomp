#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x668588
class TTransportPicture : public TPictureResourceEntryBase {
public:
  short gaugeMetricId90;
  short unknown92;
  short splitValue94;
  short splitValue96;
  short splitLimit98;

  TTransportPicture();
  virtual ~TTransportPicture();
};

ASSERT_SIZE(TTransportPicture, 0x9c);
