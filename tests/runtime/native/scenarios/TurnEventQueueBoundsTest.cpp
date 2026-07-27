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
      if (!Require("turn_event_queue.accepts_capacity", queue.Push(0x1000 + index),
                   "\"turn-event queue rejected an in-capacity event\"")) {
        return;
      }
    }
    Check("turn_event_queue.rejects_overflow",
          queue.Count() == RuntimeTurnEventQueue::kCapacity && !queue.Push(0x2000),
          "\"turn-event queue did not reject overflow\"");
    for (index = 0; index < RuntimeTurnEventQueue::kCapacity; ++index) {
      int eventCode = 0;
      Check("turn_event_queue.preserves_fifo", queue.Pop(eventCode) && eventCode == 0x1000 + index,
            "\"turn-event queue lost FIFO evidence at its capacity boundary\"");
    }
    int eventCode = 0;
    Check("turn_event_queue.empties_after_pop", queue.Count() == 0 && !queue.Pop(eventCode),
          "\"turn-event queue did not become empty after complete observation\"");
    if (FinishChecks()) {
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
