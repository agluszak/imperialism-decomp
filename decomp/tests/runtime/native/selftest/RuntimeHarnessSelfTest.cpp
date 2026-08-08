#include "RuntimeHarnessCore.h"
#include "RuntimeObservation.h"
#include "RuntimeRegistry.h"
#include "RuntimeTurnEventQueue.h"
#include "parson.h"

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
      {"alpha", 0, kRuntimeCaptureNone, "internal_invariant"},
      {"beta", 0, kRuntimeCaptureUiTree, "mac_resource_oracle"},
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
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  const char* original = "quote=\" slash=\\ line=\n tab=\t";
  bool built = object != 0 && json_object_set_string(object, "text", original) == JSONSuccess;
  char* serialized = built ? json_serialize_to_string(value) : 0;
  JSON_Value* parsed = serialized != 0 ? json_parse_string(serialized) : 0;
  JSON_Object* parsedObject = parsed != 0 ? json_value_get_object(parsed) : 0;
  const char* restored = parsedObject != 0 ? json_object_get_string(parsedObject, "text") : 0;
  Expect("json.string_roundtrip", restored != 0 && strcmp(restored, original) == 0,
         "Parson did not preserve a quoted control-string value");
  json_value_free(parsed);
  json_free_serialized_string(serialized);
  json_value_free(value);

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

void TestParsonDom() {
  JSON_Value* rootValue = json_value_init_object();
  JSON_Object* root = rootValue != 0 ? json_value_get_object(rootValue) : 0;
  JSON_Value* capturesValue = json_value_init_object();
  JSON_Object* captures = capturesValue != 0 ? json_value_get_object(capturesValue) : 0;
  JSON_Value* valuesValue = json_value_init_array();
  JSON_Array* values = valuesValue != 0 ? json_value_get_array(valuesValue) : 0;
  bool built = root != 0 && captures != 0 && values != 0;
  if (built) {
    built = json_object_set_string(root, "name", "parson_probe") == JSONSuccess &&
            json_object_set_number(root, "seed", 1) == JSONSuccess &&
            json_object_set_string(root, "status", "passed") == JSONSuccess &&
            json_array_append_number(values, 7) == JSONSuccess &&
            json_array_append_boolean(values, 1) == JSONSuccess;
  }
  if (built && json_object_set_value(captures, "probe", valuesValue) == JSONSuccess) {
    valuesValue = 0;
  } else {
    built = false;
  }
  if (built && json_object_set_value(root, "captures", capturesValue) == JSONSuccess) {
    capturesValue = 0;
  } else {
    built = false;
  }
  char* serialized = built ? json_serialize_to_string(rootValue) : 0;
  JSON_Value* parsed = serialized != 0 ? json_parse_string(serialized) : 0;
  JSON_Object* parsedRoot = parsed != 0 ? json_value_get_object(parsed) : 0;
  JSON_Object* parsedCaptures =
      parsedRoot != 0 ? json_object_get_object(parsedRoot, "captures") : 0;
  JSON_Array* probe = parsedCaptures != 0 ? json_object_get_array(parsedCaptures, "probe") : 0;
  const char* parsedName = parsedRoot != 0 ? json_object_get_string(parsedRoot, "name") : 0;
  const char* parsedStatus = parsedRoot != 0 ? json_object_get_string(parsedRoot, "status") : 0;
  Expect("json.parson_dom",
         parsedRoot != 0 && parsedName != 0 && strcmp(parsedName, "parson_probe") == 0 &&
             json_object_get_number(parsedRoot, "seed") == 1 && parsedStatus != 0 &&
             strcmp(parsedStatus, "passed") == 0 && probe != 0 &&
             json_array_get_count(probe) == 2 && json_array_get_number(probe, 0) == 7 &&
             json_array_get_boolean(probe, 1) == 1,
         "Parson did not construct and parse the runtime-result shape");
  if (serialized != 0) {
    json_free_serialized_string(serialized);
  }
  json_value_free(parsed);
  json_value_free(valuesValue);
  json_value_free(capturesValue);
  json_value_free(rootValue);
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
  TestParsonDom();

  const char* status = g_results.HasFailures() ? "failed" : "passed";
  JSON_Value* rootValue = json_value_init_object();
  JSON_Object* root = rootValue != 0 ? json_value_get_object(rootValue) : 0;
  JSON_Value* capturesValue = json_value_init_object();
  JSON_Object* captures = capturesValue != 0 ? json_value_get_object(capturesValue) : 0;
  bool resultBuilt = root != 0 && captures != 0 &&
                     json_object_set_string(root, "name", testName) == JSONSuccess &&
                     json_object_set_number(root, "seed", seed) == JSONSuccess &&
                     json_object_set_string(root, "status", status) == JSONSuccess;
  if (resultBuilt && json_object_set_value(root, "captures", capturesValue) == JSONSuccess) {
    capturesValue = 0;
  } else {
    resultBuilt = false;
  }
  char* resultJson = resultBuilt ? json_serialize_to_string_pretty(rootValue) : 0;
  bool wrote = resultJson != 0 &&
               WriteRuntimeBytesAtomically(resultPath, resultJson,
                                           static_cast<unsigned long>(strlen(resultJson)));
  json_free_serialized_string(resultJson);
  json_value_free(capturesValue);
  json_value_free(rootValue);
  if (!wrote) {
    return 3;
  }
  return g_results.HasFailures() ? 1 : 0;
}
