#pragma once

#include "game/CString.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TView;
class TMovieView;

// TODO(manifest): describe TAssetMgr and its role. Base edge (TObject) recovered from RTTI
// CRuntimeClass chain: TAssetMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066f508
class TAssetMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TAssetMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TAssetMgr)
  virtual ~TAssetMgr() override; // slot 0x01 (scalar deleting destructor)
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
  // Ground truth (0x5dfc10): two parameters only — the movie view pointer is the
  // second arg (stored into g_pUiRuntimeContext->activeMovieViewF4 at 0x5dfc8e);
  // there is no mode flag.
  virtual void
  PlayMovieClipAndDispatchTurnStateFollowup(CString movieName,
                                            TMovieView* movieView); // slot 0x0e 0x5dfc10
  // === END GENERATED DECLS (TAssetMgr) ===

  // Non-virtual resource-stream helpers (every call site loads ECX = g_pUiViewManager;
  // the callees ignore `this`). Used by the battle-setup .tab loader (0x5a4fc0).
  class CFile_Virtuals* LoadTableResourceStreamByName(CString name); // 0x5df430, body TODO
  // Reads *countInOut bytes from the stream into buffer, writes bytes-read back
  // through countInOut. 0x5df700.
  int ReadResourceStreamIntoBufferAndAdvance(class CFile_Virtuals* stream, void* buffer,
                                             int* countInOut);
  void ReleaseResourceStreamIfNotNull(class CFile_Virtuals* stream); // 0x5df6d0

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
  // Save the MFC document to `savePath`, then restamp its path with the "__saved"
  // marker so later saves re-prompt. `this` is unused; callers still dispatch it
  // through g_pUiViewManager. 0x005e0030.
  unsigned char SaveMainDocumentToPathAndMarkSaved(const CString& savePath);
  // Open the MFC document from `loadPath` (CWinApp::OpenDocumentFile) and restamp its
  // path with the "__loaded" marker; returns whether a document was opened. `this` is
  // unused; callers dispatch through g_pUiViewManager. 0x005e0150.
  unsigned char OpenMainDocumentFromPathAndMarkLoaded(const CString& loadPath);
};

void __stdcall EnsurePictWvDataGobLoadedBySlot(int languageTag);

void __stdcall ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag);

void __stdcall AssignScoresDatPathToSharedString(CString* out);
