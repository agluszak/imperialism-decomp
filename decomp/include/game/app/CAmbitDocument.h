#pragma once

#include "compat.h"

#include "game/mfc.h"

class TAmbitFileBasedDocument;

// MFC document class for the SDI doc template (CRuntimeClass @ 0x0063e7f8, m_lpszClassName
// CAmbitDocument, m_nObjectSize 0x54, vtable 0x00645eb8). The ctor also owns creating the
// global turn-event dialog-factory registry and registering the startup factories.
// VTABLE: IMPERIALISM 0x00645eb8
class CAmbitDocument : public CDocument {
public:
  DECLARE_DYNCREATE(CAmbitDocument)

  CAmbitDocument();                   // 0x479480
  virtual ~CAmbitDocument() override; // 0x479710

  // CDocument virtual overrides (vtable slots verified against 0x645eb8). IsModified /
  // SetModifiedFlag re-expose the base m_bModified; OnNewDocument/OnOpenDocument toggle the
  // multiplayer-scenario-setup flag; OnSaveDocument creates the parent directory first;
  // Serialize drives the T-tree document adapter through an ArchiveStreamAdapter.
  virtual void Serialize(CArchive& ar) override;                // 0x004797d0 (slot 0x08)
  virtual BOOL IsModified() override;                           // 0x004796a0 (slot 0x60)
  virtual void SetModifiedFlag(BOOL bModified = TRUE) override; // 0x004796c0 (slot 0x64)
  virtual BOOL OnNewDocument() override;                        // 0x004797a0 (slot 0x78)
  virtual BOOL OnOpenDocument(LPCTSTR lpszPathName) override;   // 0x00479960 (slot 0x7c)
  virtual BOOL OnSaveDocument(LPCTSTR lpszPathName) override;   // 0x00479990 (slot 0x80)

  afx_msg void OnCommand8003(); // 0x00479940, command 0x8003

  TAmbitFileBasedDocument* fileBasedDocument50; // +0x50 (4-byte T-tree document adapter)

  DECLARE_MESSAGE_MAP()
};
ASSERT_SIZE(CAmbitDocument, 0x54);
