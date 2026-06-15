#pragma once

#include "decomp_types.h"

// MFC CPlex bump-allocator block header (retail at 0x00601b74 / 0x00601b94).
struct CPlex {
  CPlex* pNext;

  static CPlex* __stdcall Create(CPlex*& head, unsigned int nMax, unsigned int cbElement);
  void FreeDataChain();
};
