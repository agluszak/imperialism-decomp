#include "RuntimeHarnessCore.h"

#include "RuntimeObservation.h"
#include "RuntimeRegistry.h"

#include <string.h>
#include <windows.h>

RuntimeProgressState::RuntimeProgressState() {
  Reset(0);
}

void RuntimeProgressState::Reset(unsigned long now) {
  finished = false;
  idleTicks = 0;
  phaseTicks = 0;
  phaseStartMs = now;
  startMs = now;
  progressCounter = 0;
  lastProgressMs = 0;
  lastHeartbeatMs = 0;
  lstrcpyA(phaseName, "not_started");
  lastAction[0] = 0;
}

void RuntimeProgressState::EnterPhase(const char* phase, const char* action, unsigned long now) {
  lstrcpynA(phaseName, phase, sizeof(phaseName));
  phaseTicks = 0;
  phaseStartMs = now;
  MarkProgress(action, now);
}

void RuntimeProgressState::Finish() {
  finished = true;
  lstrcpyA(phaseName, "finished");
}

void RuntimeProgressState::CountTick() {
  ++idleTicks;
  ++phaseTicks;
}

void RuntimeProgressState::MarkProgress(const char* action, unsigned long now) {
  lstrcpynA(lastAction, action, sizeof(lastAction));
  ++progressCounter;
  lastProgressMs = ElapsedMs(now);
}

void RuntimeProgressState::MarkFallbackProgress(unsigned long now) {
  ++progressCounter;
  lastProgressMs = ElapsedMs(now);
}

bool RuntimeProgressState::HeartbeatDue(unsigned long now, unsigned long interval) const {
  return lastHeartbeatMs == 0 || now - lastHeartbeatMs >= interval;
}

void RuntimeProgressState::ResetHeartbeat() {
  lastHeartbeatMs = 0;
}

void RuntimeProgressState::MarkHeartbeatWritten(unsigned long now) {
  lastHeartbeatMs = now;
}

bool RuntimeProgressState::IsFinished() const {
  return finished;
}

const char* RuntimeProgressState::PhaseName() const {
  return phaseName;
}

const char* RuntimeProgressState::LastAction() const {
  return lastAction;
}

unsigned long RuntimeProgressState::ElapsedMs(unsigned long now) const {
  return now - startMs;
}

unsigned long RuntimeProgressState::PhaseElapsedMs(unsigned long now) const {
  return now - phaseStartMs;
}

unsigned long RuntimeProgressState::IdleTicks() const {
  return idleTicks;
}

unsigned long RuntimeProgressState::PhaseTicks() const {
  return phaseTicks;
}

unsigned long RuntimeProgressState::ProgressCounter() const {
  return progressCounter;
}

unsigned long RuntimeProgressState::LastProgressMs() const {
  return lastProgressMs;
}

unsigned long RuntimeProgressState::LastHeartbeatMs() const {
  return lastHeartbeatMs;
}

RuntimeAwaitState::RuntimeAwaitState() {
  Clear();
}

void RuntimeAwaitState::Clear() {
  observationKinds = kObserveNone;
  armed = false;
  expression[0] = 0;
  source[0] = 0;
}

void RuntimeAwaitState::Arm(unsigned int kinds, const char* text, const char* file, int line) {
  observationKinds = kinds;
  armed = true;
  lstrcpynA(expression, text != 0 ? text : "", sizeof(expression));
  if (file != 0) {
    wsprintfA(source, "%s:%d", RuntimeSourceBasename(file), line);
  } else {
    source[0] = 0;
  }
}

bool RuntimeAwaitState::IsArmed() const {
  return armed;
}

unsigned int RuntimeAwaitState::ObservationKinds() const {
  return observationKinds;
}

const char* RuntimeAwaitState::Expression() const {
  return expression;
}

const char* RuntimeAwaitState::Source() const {
  return source;
}

RuntimeResultAggregate::RuntimeResultAggregate() {
  Reset();
}

void RuntimeResultAggregate::Reset() {
  failureCount = 0;
  firstAssertionId[0] = 0;
  firstFailure[0] = 0;
}

void RuntimeResultAggregate::RecordAssertion(const char* assertionId, const char* failure, bool) {
  ++failureCount;
  if (firstAssertionId[0] == 0) {
    lstrcpynA(firstAssertionId, assertionId, sizeof(firstAssertionId));
    lstrcpynA(firstFailure, failure, sizeof(firstFailure));
  }
}

bool RuntimeResultAggregate::HasFailures() const {
  return failureCount != 0;
}

int RuntimeResultAggregate::FailureCount() const {
  return failureCount;
}

const char* RuntimeResultAggregate::FirstAssertionId() const {
  return firstAssertionId;
}

const char* RuntimeResultAggregate::FirstFailure() const {
  return firstFailure;
}

const char* RuntimeSourceBasename(const char* path) {
  if (path == 0) {
    return "";
  }
  const char* name = path;
  for (const char* cursor = path; *cursor != 0; ++cursor) {
    // __FILE__ arrives as a Wine path, so both separators have to be honoured.
    if (*cursor == '\\' || *cursor == '/') {
      name = cursor + 1;
    }
  }
  return name;
}

bool DescribeRuntimeObservationMask(unsigned int observationKinds, char* text,
                                    unsigned long capacity) {
  struct NamedKind {
    unsigned int kind;
    const char* name;
  };
  // Order is stable so heartbeat diffs stay readable across runs.
  static const NamedKind kNames[] = {
      {kObserveApplicationIdle, "application_idle"},
      {kObserveMainViewChanged, "main_view_changed"},
      {kObserveModalPushed, "modal_pushed"},
      {kObserveModalPopped, "modal_popped"},
      {kObserveAnimationAdded, "animation_added"},
      {kObserveAnimationRemoved, "animation_removed"},
      {kObservePaintCompleted, "paint_completed"},
      {kObserveInvalidationRequested, "invalidation_requested"},
      {kObserveTurnEventActivated, "turn_event_activated"},
      {kObserveUiTreeBuilt, "ui_tree_built"},
      {kObserveGameStateChanged, "game_state_changed"},
      {kObserveRuntimeBarrier, "runtime_barrier"},
  };
  const int kNameCount = sizeof(kNames) / sizeof(kNames[0]);

  if (capacity < 2) {
    return false;
  }
  text[0] = 0;

  // AwaitUiChange's composite is by far the most common wait; naming it beats listing
  // eleven flags every time. lstrcpynA would truncate silently, so these fixed names go
  // through the same capacity check as the assembled list below -- a description that does
  // not fit must report failure, not a shortened half-truth.
  const char* fixedName = 0;
  if (observationKinds == kObserveNone) {
    fixedName = "none";
  } else if (observationKinds == kObserveUiStateChanged) {
    fixedName = "ui_state_changed";
  } else if (observationKinds == (kObserveUiStateChanged | kObserveApplicationIdle)) {
    fixedName = "ui_state_changed|application_idle";
  }
  if (fixedName != 0) {
    if (static_cast<unsigned long>(strlen(fixedName)) + 1 > capacity) {
      lstrcpynA(text, "?", capacity);
      return false;
    }
    lstrcpyA(text, fixedName);
    return true;
  }

  unsigned long length = 0;
  unsigned int remaining = observationKinds;
  for (int index = 0; index < kNameCount; ++index) {
    if ((observationKinds & kNames[index].kind) == 0) {
      continue;
    }
    remaining &= ~kNames[index].kind;
    unsigned long nameLength = static_cast<unsigned long>(strlen(kNames[index].name));
    unsigned long needed = length + nameLength + (length != 0 ? 1 : 0) + 1;
    if (needed > capacity) {
      lstrcpynA(text, "?", capacity);
      return false;
    }
    if (length != 0) {
      text[length++] = '|';
    }
    memcpy(text + length, kNames[index].name, nameLength);
    length += nameLength;
    text[length] = 0;
  }
  if (remaining != 0) {
    // An unnamed bit means the enum grew without this table; say so rather than lie.
    char unknown[24];
    wsprintfA(unknown, "%s0x%x", length != 0 ? "|" : "", remaining);
    unsigned long unknownLength = static_cast<unsigned long>(strlen(unknown));
    if (length + unknownLength + 1 > capacity) {
      lstrcpynA(text, "?", capacity);
      return false;
    }
    memcpy(text + length, unknown, unknownLength);
    length += unknownLength;
    text[length] = 0;
  }
  return true;
}

int FindRuntimeDescriptorIndex(const char* name, const RuntimeTestDescriptor* descriptors,
                               int count) {
  for (int index = 0; index < count; ++index) {
    if (strcmp(descriptors[index].name, name) == 0) {
      return index;
    }
  }
  return -1;
}

bool EscapeRuntimeJsonString(const char* value, char* escaped, unsigned long capacity) {
  unsigned long length = 0;
  if (capacity < 3) {
    return false;
  }
  escaped[length++] = '"';
  const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value);
  for (; *cursor != 0; ++cursor) {
    char control[7];
    const char* addition = 0;
    char literal[2];
    switch (*cursor) {
    case '"':
      addition = "\\\"";
      break;
    case '\\':
      addition = "\\\\";
      break;
    case '\n':
      addition = "\\n";
      break;
    case '\r':
      addition = "\\r";
      break;
    case '\t':
      addition = "\\t";
      break;
    default:
      if (*cursor < 0x20) {
        wsprintfA(control, "\\u%04x", static_cast<unsigned int>(*cursor));
        addition = control;
      } else {
        literal[0] = static_cast<char>(*cursor);
        literal[1] = 0;
        addition = literal;
      }
      break;
    }
    unsigned long additionLength = static_cast<unsigned long>(strlen(addition));
    if (length + additionLength + 2 > capacity) {
      escaped[0] = 0;
      return false;
    }
    memcpy(escaped + length, addition, additionLength);
    length += additionLength;
  }
  escaped[length++] = '"';
  escaped[length] = 0;
  return true;
}

namespace {

bool WriteAll(HANDLE file, const char* bytes, DWORD size) {
  DWORD written = 0;
  return WriteFile(file, bytes, size, &written, 0) != 0 && written == size;
}

} // namespace

bool WriteRuntimeBytesAtomically(const char* path, const char* bytes, unsigned long size) {
  char temporaryPath[MAX_PATH];
  if (strlen(path) + 4 >= sizeof(temporaryPath)) {
    return false;
  }
  lstrcpyA(temporaryPath, path);
  lstrcatA(temporaryPath, ".tmp");
  HANDLE file =
      CreateFileA(temporaryPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  bool wrote = WriteAll(file, bytes, static_cast<DWORD>(size));
  if (wrote) {
    wrote = FlushFileBuffers(file) != 0;
  }
  CloseHandle(file);
  if (!wrote) {
    DeleteFileA(temporaryPath);
    return false;
  }
  if (MoveFileExA(temporaryPath, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    DeleteFileA(temporaryPath);
    return false;
  }
  return true;
}
