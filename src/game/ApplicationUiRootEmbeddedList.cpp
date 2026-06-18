#include "game/ApplicationUiRootEmbeddedList.h"

#include "game/mfc.h"

ApplicationUiRootEmbeddedList::ApplicationUiRootEmbeddedList()
    : head(0), field08(0), field0c(0), field10(0), field14(0), blockSize(10) {}

// FUNCTION: IMPERIALISM 0x00486df0
void ApplicationUiRootEmbeddedList::Serialize(CArchive& archive) {
  if (archive.IsLoading()) {
    UINT count = archive.ReadCount();
    for (; count != 0; count--) {
      int value = 0;
      archive.Read(&value, 4);

      int* node = AllocateNode();
      node[1] = field08;
      node[0] = 0;
      field0c = field0c + 1;
      node[2] = value;
      if (field08 == 0) {
        head = node;
      } else {
        *reinterpret_cast<int**>(field08) = node;
      }
      field08 = reinterpret_cast<int>(node);
    }
    return;
  }

  archive.WriteCount(static_cast<DWORD>(field0c));
  for (int* node = reinterpret_cast<int*>(head); node != 0;
       node = reinterpret_cast<int*>(node[0])) {
    archive.Write(&node[2], 4);
  }
}

// FUNCTION: IMPERIALISM 0x00486f90
ApplicationUiRootEmbeddedList::~ApplicationUiRootEmbeddedList() {
  for (void** cursor = reinterpret_cast<void**>(head); cursor != 0;
       cursor = reinterpret_cast<void**>(*cursor)) {
  }
  field0c = 0;
  field10 = 0;
  field08 = 0;
  head = 0;
  if (field14 != 0) {
    reinterpret_cast<CPlex*>(field14)->FreeDataChain();
  }
  field14 = 0;
}

// SYNTHETIC: IMPERIALISM 0x00486f60
// ApplicationUiRootEmbeddedList::`scalar deleting destructor'
