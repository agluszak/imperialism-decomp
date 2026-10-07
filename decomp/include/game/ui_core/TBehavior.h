#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/app/TObject.h"

class TEventHandler;

// VTABLE: IMPERIALISM 0x00648d60
class TBehavior : public TObject {
public:
  // FUNCTION: IMPERIALISM 0x00487240
  virtual ~TBehavior() override {}
  TBehavior();

  DECLARE_DYNCREATE(TBehavior)
  void SetBehaviorTag(unsigned long tag);
  virtual void SetOwner(TEventHandler* owner);
  virtual unsigned char IsEnabled();
  virtual void SetEnabled(bool enabled);
  virtual void Draw(RECT* bounds);

  unsigned long behaviorTag;
  TEventHandler* owner;
  bool enabled;
  unsigned char padding0d[3];
};

ASSERT_SIZE(TBehavior, 0x10);
