#pragma once

#include "game/TObject.h"

// Thin TObject wrapper that carries a CArchive* for TFileStream serialization.
// Layout: TObject vptr (+0), CArchive* archive (+4).
// VTABLE: IMPERIALISM 0x00645f98
class ArchiveStreamAdapter : public TObject {
public:
  CArchive* archive;

  ArchiveStreamAdapter(CArchive* pArchive) : archive(pArchive) {}
};

ASSERT_SIZE(ArchiveStreamAdapter, 0x8);
