// Owner TU: constructors/destructors of the two embedding classes. The matrix
// driver compiles this at each /Ob level and inventories which template COMDATs
// this TU emits (~CList, scalar deleting dtor, Serialize, NewNode, ...).
#include "probe.h"

#ifdef PROBE_EXPLICIT_INIT
EmbeddedVoidList::EmbeddedVoidList() : before(0), after(0) {}
EmbeddedPodList::EmbeddedPodList() : before(0), after(0) {}
#else
EmbeddedVoidList::EmbeddedVoidList() {
  before = 0;
  after = 0;
}
EmbeddedPodList::EmbeddedPodList() {
  before = 0;
  after = 0;
}
#endif

#ifdef PROBE_NONEMPTY_DTOR
static int g_dtorTicks = 0;
EmbeddedVoidList::~EmbeddedVoidList() {
  ++g_dtorTicks;
}
EmbeddedPodList::~EmbeddedPodList() {
  ++g_dtorTicks;
}
#else
EmbeddedVoidList::~EmbeddedVoidList() {}
EmbeddedPodList::~EmbeddedPodList() {}
#endif

#ifdef PROBE_SAME_TU
// Same-TU users: does co-location change which COMDATs land here?
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
