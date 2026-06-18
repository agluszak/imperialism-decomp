#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

// Embedded CObList-like prefix at ApplicationUiRootController+0x2c.
// VTABLE: IMPERIALISM 0x00648ca8
class ApplicationUiRootEmbeddedList : public CObject {
public:
  void Serialize(CArchive& archive) override;

  void* head;    // +0x04 (global 0x30)
  int field08;   // +0x08 (global 0x34)
  int field0c;   // +0x0c (global 0x38)
  int field10;   // +0x10 (global 0x3c)
  int field14;   // +0x14 (global 0x40)
  int blockSize; // +0x18 (global 0x44) — ctor writes 10

  ApplicationUiRootEmbeddedList();
  int* AllocateNode() {
    if (field10 == 0) {
      CPlex*& chain = *reinterpret_cast<CPlex**>(&field14);
      CPlex* newBlock = CPlex::Create(chain, static_cast<unsigned int>(blockSize), 0xc);
      int blockBase = reinterpret_cast<int>(newBlock);
      int entryCount = blockSize;
      int* cursor = reinterpret_cast<int*>(blockBase + (entryCount * 0xc) - 8);
      for (entryCount = entryCount - 1; entryCount >= 0; entryCount = entryCount - 1) {
        *cursor = field10;
        field10 = reinterpret_cast<int>(cursor);
        cursor = cursor - 3;
      }
    }

    int* node = reinterpret_cast<int*>(field10);
    field10 = node[0];
    return node;
  }

protected:
  ~ApplicationUiRootEmbeddedList() override;
  friend class ApplicationUiRootController;
};

ASSERT_SIZE(ApplicationUiRootEmbeddedList, 0x1c);
