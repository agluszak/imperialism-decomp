#pragma once

#include "compat.h"

#include "game/mfc.h"

class TAmbitFileBasedDocument;

// VTABLE: IMPERIALISM 0x00645eb8
class CAmbitDocument : public CDocument {
public:
  DECLARE_DYNCREATE(CAmbitDocument)

  CAmbitDocument();                   // 0x479480
  virtual ~CAmbitDocument() override; // 0x479710

  virtual void Serialize(CArchive& ar) override;                // 0x004797d0 (slot 0x08)
  virtual BOOL IsModified() override;                           // 0x004796a0 (slot 0x60)
  virtual void SetModifiedFlag(BOOL bModified = TRUE) override; // 0x004796c0 (slot 0x64)
  virtual BOOL OnNewDocument() override;                        // 0x004797a0 (slot 0x78)
  virtual BOOL OnOpenDocument(LPCTSTR lpszPathName) override;   // 0x00479960 (slot 0x7c)
  virtual BOOL OnSaveDocument(LPCTSTR lpszPathName) override;   // 0x00479990 (slot 0x80)

  afx_msg void OnStartNextPhase(); // 0x00479940

  TAmbitFileBasedDocument* fileBasedDocument; // +0x50 (4-byte T-tree document adapter)

  DECLARE_MESSAGE_MAP()
};
ASSERT_SIZE(CAmbitDocument, 0x54);
