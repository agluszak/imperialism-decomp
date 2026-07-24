#include "RuntimeScenario.h"

#include "../RuntimeHarness.h"

namespace {

class TurnEventQueueBoundsTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "turn_event_queue_bounds";
  }

  void OnManagersReady() override {
    RuntimeTurnEventQueue queue;
    int index;
    for (index = 0; index < RuntimeTurnEventQueue::kCapacity; ++index) {
      if (!queue.Push(0x1000 + index)) {
        FailScenario("\"turn-event queue rejected an in-capacity event\"");
        return;
      }
    }
    if (queue.Count() != RuntimeTurnEventQueue::kCapacity || queue.Push(0x2000)) {
      FailScenario("\"turn-event queue did not reject overflow\"");
      return;
    }
    for (index = 0; index < RuntimeTurnEventQueue::kCapacity; ++index) {
      int eventCode = 0;
      if (!queue.Pop(eventCode) || eventCode != 0x1000 + index) {
        FailScenario("\"turn-event queue lost FIFO evidence at its capacity boundary\"");
        return;
      }
    }
    int eventCode = 0;
    if (queue.Count() != 0 || queue.Pop(eventCode)) {
      FailScenario("\"turn-event queue did not become empty after complete observation\"");
      return;
    }
    Pass();
  }
};

TurnEventQueueBoundsTestCase g_test;

} // namespace

RuntimeTestCase* TurnEventQueueBoundsTest() {
  return &g_test;
}
