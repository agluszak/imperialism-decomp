#pragma once

#include "game/mfc.h"

class TAmbitFileBasedDocument;

// MFC document class for the SDI doc template (CRuntimeClass @ 0x0063e7f8, m_lpszClassName
// CAmbitDocument, m_nObjectSize 0x54, vtable 0x00645eb8). The ctor also owns creating the
// global turn-event dialog-factory registry and registering the startup factories.
// vtable 0x00645eb8 (no // VTABLE: marker yet — reaching 100% needs the CDocument-specific
// override methods modelled: Serialize 0x4797d0, OnNewDocument/OnSaveDocument/OnOpenDocument,
// the two game virtuals at 0x4796a0/0x4796c0, GetMessageMap + scalar dtor, plus the CDocument
// library slots. Tracked as a follow-up; symbols.csv no longer carries a stray vftable row.)
class CAmbitDocument : public CDocument {
public:
  DECLARE_DYNCREATE(CAmbitDocument)

  CAmbitDocument();                   // 0x479480
  virtual ~CAmbitDocument() override; // 0x479710

  // Re-expose the protected CDocument save entry point: the save flow
  // (TAssetMgr::SaveMainDocumentToPathAndMarkSaved, 0x5e0030) drives DoSave directly on
  // the active document instead of going through DoFileSave.
  using CDocument::DoSave;

  TAmbitFileBasedDocument* fileBasedDocument50; // +0x50 (4-byte T-tree document adapter)
};
