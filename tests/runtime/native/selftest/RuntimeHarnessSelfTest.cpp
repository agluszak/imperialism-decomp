#include "RuntimeHarnessCore.h"
#include "RuntimeObservation.h"
#include "RuntimeRegistry.h"
#include "RuntimeTurnEventQueue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

namespace {

RuntimeResultAggregate g_results;

void Expect(const char* id, bool condition, const char* failure) {
  if (!condition) {
    g_results.RecordAssertion(id, failure, true);
  }
}

void TestTurnEventQueue() {
  RuntimeTurnEventQueue queue;
  int index;
  for (index = 0; index < RuntimeTurnEventQueue::kCapacity; ++index) {
    Expect("queue.accepts_capacity", queue.Push(0x1000 + index),
           "queue rejected an in-capacity event");
  }
  Expect("queue.rejects_overflow", !queue.Push(0x2000), "queue accepted overflow");
  for (index = 0; index < RuntimeTurnEventQueue::kCapacity; ++index) {
    int value = 0;
    Expect("queue.preserves_fifo", queue.Pop(value) && value == 0x1000 + index,
           "queue did not preserve FIFO ordering");
  }
  int value = 0;
  Expect("queue.empties", !queue.Pop(value) && queue.Count() == 0, "queue did not become empty");
}

void TestTransitionsAndHeartbeat() {
  RuntimeProgressState progress;
  progress.Reset(100);
  progress.EnterPhase("loading", "open_fixture", 120);
  progress.CountTick();
  progress.CountTick();
  Expect("transition.phase", strcmp(progress.PhaseName(), "loading") == 0,
         "phase transition was not retained");
  Expect("transition.action", strcmp(progress.LastAction(), "open_fixture") == 0,
         "transition action was not retained");
  Expect("transition.counters", progress.IdleTicks() == 2 && progress.PhaseTicks() == 2,
         "transition tick counters diverged");
  Expect("heartbeat.initial", progress.HeartbeatDue(120, 250), "initial heartbeat was suppressed");
  progress.MarkHeartbeatWritten(120);
  Expect("heartbeat.throttle", !progress.HeartbeatDue(369, 250),
         "heartbeat throttle emitted too early");
  Expect("heartbeat.resume", progress.HeartbeatDue(370, 250), "heartbeat throttle did not reopen");
  progress.MarkFallbackProgress(375);
  Expect("heartbeat.progress", progress.ProgressCounter() == 2 && progress.LastProgressMs() == 275,
         "fallback progress was not aggregated");
  progress.Finish();
  Expect("transition.finish",
         progress.IsFinished() && strcmp(progress.PhaseName(), "finished") == 0,
         "finish transition was not retained");
}

void TestAwaitState() {
  RuntimeAwaitState await;
  Expect("await.initially_clear", !await.IsArmed() && await.Expression()[0] == 0,
         "await state started out armed");

  await.Arm(kObservePaintCompleted | kObserveGameStateChanged, "bid->glyphBase84 != initialBitmap",
            "Z:\\imperialism\\tests\\runtime\\native\\scenarios\\TradeScreenTest.cpp", 402);
  Expect("await.armed", await.IsArmed(), "arming did not take effect");
  Expect("await.expression", strcmp(await.Expression(), "bid->glyphBase84 != initialBitmap") == 0,
         "await state dropped the expression it was given");
  // __FILE__ is an absolute Wine path; only the basename belongs in a diagnostic.
  Expect("await.source", strcmp(await.Source(), "TradeScreenTest.cpp:402") == 0,
         "await source was not reduced to basename:line");
  Expect("await.mask",
         await.ObservationKinds() == (kObservePaintCompleted | kObserveGameStateChanged),
         "await state lost its observation mask");

  await.Clear();
  Expect("await.cleared", !await.IsArmed() && await.Source()[0] == 0,
         "clearing left the await state armed");
}

void TestObservationMaskDescription() {
  char text[256];
  Expect("mask.none",
         DescribeRuntimeObservationMask(kObserveNone, text, sizeof(text)) &&
             strcmp(text, "none") == 0,
         "an empty mask did not describe itself as none");
  Expect("mask.single",
         DescribeRuntimeObservationMask(kObserveModalPopped, text, sizeof(text)) &&
             strcmp(text, "modal_popped") == 0,
         "a single-bit mask did not name its observation");
  Expect("mask.pair",
         DescribeRuntimeObservationMask(kObservePaintCompleted | kObserveGameStateChanged, text,
                                        sizeof(text)) &&
             strcmp(text, "paint_completed|game_state_changed") == 0,
         "a two-bit mask did not join its names in enum order");
  // AwaitUiChange's composite is the most common wait; naming it keeps it readable.
  Expect("mask.composite",
         DescribeRuntimeObservationMask(kObserveUiStateChanged, text, sizeof(text)) &&
             strcmp(text, "ui_state_changed") == 0,
         "the UI-state composite did not collapse to its own name");
  Expect("mask.composite_with_idle",
         DescribeRuntimeObservationMask(kObserveUiStateChanged | kObserveApplicationIdle, text,
                                        sizeof(text)) &&
             strcmp(text, "ui_state_changed|application_idle") == 0,
         "the UI-state composite plus idle did not collapse");
  // A bit with no name means the enum grew without the table; say so rather than lie.
  Expect("mask.unknown_bit",
         DescribeRuntimeObservationMask(kObserveModalPushed | 0x80000000u, text, sizeof(text)) &&
             strcmp(text, "modal_pushed|0x80000000") == 0,
         "an unnamed observation bit was silently dropped");
  char small[4];
  Expect("mask.overflow",
         !DescribeRuntimeObservationMask(kObserveUiStateChanged, small, sizeof(small)),
         "a too-small buffer was reported as a successful description");
}

void TestSourceBasename() {
  Expect("basename.windows",
         strcmp(RuntimeSourceBasename("Z:\\imperialism\\tests\\EndTurnTest.cpp"),
                "EndTurnTest.cpp") == 0,
         "a Wine path was not reduced to its basename");
  Expect("basename.posix",
         strcmp(RuntimeSourceBasename("tests/runtime/native/EndTurnTest.cpp"), "EndTurnTest.cpp") ==
             0,
         "a POSIX path was not reduced to its basename");
  Expect("basename.bare", strcmp(RuntimeSourceBasename("EndTurnTest.cpp"), "EndTurnTest.cpp") == 0,
         "a bare file name was altered");
  Expect("basename.null", RuntimeSourceBasename(0)[0] == 0, "a null path did not yield empty text");
}

void TestRegistryLookup() {
  RuntimeTestDescriptor descriptors[] = {
      {"alpha", 0, kRuntimeSnapshotNone, "internal_invariant"},
      {"beta", 0, kRuntimeSnapshotUi, "mac_resource_oracle"},
  };
  Expect("registry.first", FindRuntimeDescriptorIndex("alpha", descriptors, 2) == 0,
         "registry missed its first descriptor");
  Expect("registry.second", FindRuntimeDescriptorIndex("beta", descriptors, 2) == 1,
         "registry missed its second descriptor");
  Expect("registry.unknown", FindRuntimeDescriptorIndex("gamma", descriptors, 2) == -1,
         "registry accepted an unknown descriptor");
}

void TestResultAggregation() {
  RuntimeResultAggregate aggregate;
  aggregate.RecordAssertion("first.assertion", "first failure", false);
  aggregate.RecordAssertion("second.assertion", "second failure", true);
  Expect("result.failure_count", aggregate.HasFailures() && aggregate.FailureCount() == 2,
         "result aggregation lost an assertion");
  Expect("result.first_assertion",
         strcmp(aggregate.FirstAssertionId(), "first.assertion") == 0 &&
             strcmp(aggregate.FirstFailure(), "first failure") == 0,
         "result aggregation did not preserve the first failure");
  aggregate.Reset();
  Expect("result.reset", !aggregate.HasFailures() && aggregate.FirstAssertionId()[0] == 0,
         "result aggregation leaked across runs");
}

void TestJsonAndAtomicWriting(const char* resultPath) {
  char escaped[128];
  bool escapedOkay =
      EscapeRuntimeJsonString("quote=\" slash=\\ line=\n tab=\t", escaped, sizeof(escaped));
  Expect("json.escape",
         escapedOkay && strcmp(escaped, "\"quote=\\\" slash=\\\\ line=\\n tab=\\t\"") == 0,
         "JSON escaping changed semantics");

  char probePath[MAX_PATH];
  lstrcpynA(probePath, resultPath, sizeof(probePath));
  lstrcatA(probePath, ".atomic");
  const char first[] = "first";
  const char second[] = "second";
  bool wroteFirst = WriteRuntimeBytesAtomically(probePath, first, sizeof(first) - 1);
  bool wroteSecond = WriteRuntimeBytesAtomically(probePath, second, sizeof(second) - 1);
  char contents[16];
  contents[0] = 0;
  FILE* file = fopen(probePath, "rb");
  if (file != 0) {
    size_t read = fread(contents, 1, sizeof(contents) - 1, file);
    contents[read] = 0;
    fclose(file);
  }
  DeleteFileA(probePath);
  Expect("json.atomic_replace", wroteFirst && wroteSecond && strcmp(contents, second) == 0,
         "atomic JSON publication did not replace the complete file");
}

} // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    return 2;
  }
  const char* resultPath = argv[1];
  const char* testName = argv[2];
  unsigned int seed = static_cast<unsigned int>(strtoul(argv[3], 0, 10));

  g_results.Reset();
  TestTurnEventQueue();
  TestTransitionsAndHeartbeat();
  TestAwaitState();
  TestObservationMaskDescription();
  TestSourceBasename();
  TestRegistryLookup();
  TestResultAggregation();
  TestJsonAndAtomicWriting(resultPath);

  char json[2048];
  const char* status = g_results.HasFailures() ? "failed" : "passed";
  const char* failure = g_results.HasFailures() ? g_results.FirstFailure() : "";
  const char* assertion = g_results.HasFailures() ? g_results.FirstAssertionId() : "";
  wsprintfA(json,
            "{\n  \"format_version\": 1,\n  \"name\": \"%s\",\n  \"seed\": %u,\n"
            "  \"status\": \"%s\",\n  \"phase\": \"finished\",\n"
            "  \"last_action\": \"native_harness_self_test\",\n"
            "  \"evidence_kind\": \"internal_invariant\",\n"
            "  \"assertion_id\": \"%s\",\n  \"failure\": \"%s\",\n"
            "  \"checks\": {\"failures\": %d}\n}\n",
            testName, seed, status, assertion, failure, g_results.FailureCount());
  if (!WriteRuntimeBytesAtomically(resultPath, json, static_cast<unsigned long>(strlen(json)))) {
    return 3;
  }
  return g_results.HasFailures() ? 1 : 0;
}
