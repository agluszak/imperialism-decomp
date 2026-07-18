// Template-emission probe types (docs/toolchain.md "template-emission compiler
// matrix"). Two owners embedding MFC CList<> members between scalar fields,
// mirroring the CIncludeView/TApplication shapes. Variant axes are selected by
// preprocessor defines from the matrix driver:
//   PROBE_EXPLICIT_INIT  - owner ctor initializes scalars via the mem-init list
//   PROBE_NONEMPTY_DTOR  - owner dtor has owner-specific work before member dtors
//   PROBE_USE_WRAPPER    - users call AddTail through a non-inline wrapper
#pragma once

#include <afxwin.h>
#include <afxtempl.h>

struct ProbeRecord {
  int a;
  int b;
  short c;
};

class EmbeddedVoidList {
public:
  EmbeddedVoidList();
  ~EmbeddedVoidList();
  int before;
  CList<void*, void*> list; // +0x04
  int after;
};

class EmbeddedPodList {
public:
  EmbeddedPodList();
  ~EmbeddedPodList();
  int before;
  CList<ProbeRecord, ProbeRecord&> list; // +0x04
  int after;
};

void UseVoidList(EmbeddedVoidList* owner, void* value);
void UsePodList(EmbeddedPodList* owner, ProbeRecord& value);
