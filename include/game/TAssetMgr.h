#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TView;

// TODO(manifest): describe TAssetMgr and its role. Base edge (TObject) recovered from RTTI
// CRuntimeClass chain: TAssetMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066f508
class TAssetMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TAssetMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TAssetMgr)
  virtual ~TAssetMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual TView*
  ResolveTurnEventDialogNodeByMessageContext(int messageContext); // slot 0x0a 0x5df3c0
  virtual void NoOpRuntimeUiCallback_005df780(int arg);           // slot 0x0b 0x5df780
  virtual void NoOpRuntimeUiCallback_005df3f0(int arg);           // slot 0x0c 0x5df3f0
  virtual void NoOpRuntimeUiCallback_005df410(int arg);           // slot 0x0d 0x5df410
  virtual void
  PlayMovieClipAndDispatchTurnStateFollowup(CString movieName,
                                            int followupEventCode); // slot 0x0e 0x5dfc10
  // === END GENERATED DECLS (TAssetMgr) ===

  // Layout recovered from ctor 0x5df280: the 13 shared UI string-reference slots live at
  // offset 0x20, preceded by an as-yet-unidentified 0x1c-byte region and followed by one
  // trailing word; sizeof(TAssetMgr) per RTTI is 0x58. The ctor default-constructs all 13
  // entries via the EH array-construct helper; the scalar deleting dtor (0x5df300) tears
  // them down with the matching array-destroy helper.
  int unknownRegion04[7];       // +0x04 .. 0x20 (purpose not yet recovered)
  CString sharedTextSlots[0xd]; // +0x20 .. 0x54
  int unknown54;                // +0x54

  TAssetMgr();
  void EnsurePictWvDataGobLoadedForLanguageSlot(int languageTag);
};

void __stdcall EnsurePictWvDataGobLoadedBySlot(int languageTag);

void __stdcall ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag);

// === BEGIN GENERATED (TAssetMgr) — refreshed by `just gen-class TAssetMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066f508 (15 slots), object size 0x58, base TObject
//   slot 0x00  byte 0x00  0x005df260  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005df300  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005df3c0  override  ResolveTurnEventDialogNodeByMessageContext
//   slot 0x0b  byte 0x2c  0x005df780  override  NoOpRuntimeUiCallback_005df780
//   slot 0x0c  byte 0x30  0x005df3f0  override  NoOpRuntimeUiCallback_005df3f0
//   slot 0x0d  byte 0x34  0x005df410  override  NoOpRuntimeUiCallback_005df410
//   slot 0x0e  byte 0x38  0x005dfc10  override  PlayMovieClipAndDispatchTurnStateFollowup
// object size 0x58 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAssetMgr) ===
