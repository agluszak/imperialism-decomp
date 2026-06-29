#include "game/TObject.h"

#include "game/ArchiveStreamAdapter.h"
#include "game/TFileStream.h"

// FUNCTION: IMPERIALISM 0x00485e90
void TObject::Serialize(CArchive& archive) {
  ArchiveStreamAdapter adapter(&archive);
  TFileStream stream;
  stream.SetBackingArchive(&adapter);

  if (archive.IsLoading()) {
    ReadFrom(&stream);
  } else {
    WriteTo(&stream);
  }
}
