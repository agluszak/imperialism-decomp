// Split-TU users of the embedded lists: which template COMDATs does a TU that
// only CALLS collection methods emit, and does routing AddTail through a
// non-inline wrapper change the call shape / emission set?
#include "probe.h"

#ifndef PROBE_SAME_TU

#ifdef PROBE_USE_WRAPPER
void AddTailVoidWrapper(CList<void*, void*>& list, void* value);
void AddTailPodWrapper(CList<ProbeRecord, ProbeRecord&>& list, ProbeRecord& value);

void UseVoidList(EmbeddedVoidList* owner, void* value) {
  AddTailVoidWrapper(owner->list, value);
  if (!owner->list.IsEmpty()) {
    owner->list.RemoveTail();
  }
}
void UsePodList(EmbeddedPodList* owner, ProbeRecord& value) {
  AddTailPodWrapper(owner->list, value);
  if (!owner->list.IsEmpty()) {
    owner->list.RemoveTail();
  }
}

void AddTailVoidWrapper(CList<void*, void*>& list, void* value) {
  list.AddTail(value);
}
void AddTailPodWrapper(CList<ProbeRecord, ProbeRecord&>& list, ProbeRecord& value) {
  list.AddTail(value);
}
#else
void UseVoidList(EmbeddedVoidList* owner, void* value) {
  owner->list.AddTail(value);
  if (!owner->list.IsEmpty()) {
    owner->list.RemoveTail();
  }
}
void UsePodList(EmbeddedPodList* owner, ProbeRecord& value) {
  owner->list.AddTail(value);
  if (!owner->list.IsEmpty()) {
    owner->list.RemoveTail();
  }
}
#endif

#endif // !PROBE_SAME_TU
