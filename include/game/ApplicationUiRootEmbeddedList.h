#pragma once

#include "decomp_types.h"

// Embedded CObList-like prefix at ApplicationUiRootController+0x2c.
// VTABLE: IMPERIALISM 0x00648ca8
class ApplicationUiRootEmbeddedList {
public:
  virtual void* GetCObjectRuntimeClass();

  void* head;       // +0x04 (global 0x30)
  int field08;      // +0x08 (global 0x34)
  int field0c;      // +0x0c (global 0x38)
  int field10;      // +0x10 (global 0x3c)
  int field14;      // +0x14 (global 0x40)
  int blockSize;    // +0x18 (global 0x44) — ctor writes 10

  ApplicationUiRootEmbeddedList();
protected:
  ~ApplicationUiRootEmbeddedList() {}
  friend class ApplicationUiRootController;
};
