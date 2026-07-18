#pragma once

#include "game/TFileBasedDocument.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c170
class TAmbitFileBasedDocument : public TFileBasedDocument {
public:
  DECLARE_DYNCREATE(TAmbitFileBasedDocument)
  virtual ~TAmbitFileBasedDocument() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // Arity corrected against RET-imm evidence (lockstep with the TDocument base slots):
  // both are RET 0x8 = 2 stack dwords; the caller passes (adapter, 0).
  virtual undefined OrphanRetStub_00486530(ArchiveStreamAdapter* stream,
                                           int flag) override; // slot 0x0a 0x49e6a0
  virtual undefined OrphanRetStub_00486550(ArchiveStreamAdapter* stream,
                                           int flag) override; // slot 0x0b 0x49eb30
  // RET 0x8 = 2 dwords (3-byte no-op; args vestigial). slot 0x0c 0x49e660
  virtual undefined OrphanRetStub_0049e660(int arg1, int arg2);
  // RET 0x4 = 1 dword (3-byte no-op; arg vestigial). slot 0x0d 0x49e680
  virtual undefined OrphanRetStub_0049e680(int arg);
  // RET 0x4 = 1 dword (asserts D:\Ambit\Cross\UAmbit.cpp:1335; arg vestigial). slot 0x0e 0x49ee70
  virtual undefined AssertUAmbitLine1335(int arg);

  TAmbitFileBasedDocument();
};
