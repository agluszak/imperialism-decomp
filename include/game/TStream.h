#pragma once

#include "CObject.h"

// MFC-style serialization stream hierarchy base (TStream family). Each concrete
// stream installs its own vtable and is reset to the shared CObject runtime
// vtable on teardown.
class TStream : public CObject {
 public:
  // virtual stream API slots, initially with conservative names.
};
