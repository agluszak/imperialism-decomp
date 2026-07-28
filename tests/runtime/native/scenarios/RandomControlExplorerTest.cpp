#include "RuntimeScenario.h"
#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeUiDriver.h"
#include "flows/RandomGameFlow.h"

#include "game/core/global_data_tables.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TView.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

namespace {

enum ReplayReadResult { kReplayEnd = 0, kReplayAction = 1, kReplayInvalid = -1 };

int TagOccurrenceBefore(TView* parent, TView* target) {
  if (parent == 0 || parent->childList44 == 0) {
    return 1;
  }
  int occurrence = 1;
  POSITION position = parent->childList44->GetHeadPosition();
  while (position != 0) {
    TView* sibling = parent->childList44->GetNext(position);
    if (sibling == target) {
      break;
    }
    if (sibling->controlTag == target->controlTag) {
      ++occurrence;
    }
  }
  return occurrence;
}

CString ViewPath(TView* view, const CString& parentPath) {
  CString segment;
  segment.Format("%08x#%d", static_cast<unsigned int>(view->controlTag),
                 TagOccurrenceBefore(view->ownerContext, view));
  if (parentPath.IsEmpty()) {
    return segment;
  }
  return parentPath + "/" + segment;
}

unsigned long EnvironmentUnsigned(const char* name, unsigned long fallback,
                                  bool allowZero = false) {
  char value[32];
  DWORD length = GetEnvironmentVariableA(name, value, sizeof(value));
  if (length == 0 || length >= sizeof(value)) {
    return fallback;
  }
  char* end = 0;
  unsigned long parsed = strtoul(value, &end, 10);
  if (end == value || *end != 0 || (!allowZero && parsed == 0)) {
    return fallback;
  }
  return parsed;
}

class RandomControlExplorerTestCase : public RandomGameScenario {
public:
  RandomControlExplorerTestCase()
      : randomState(1), actionCount(0), maxActions(500), settleTicks(2), cooldownTicks(0),
        replayOffset(0), replayMode(false), selectedView(0), candidateCount(0) {
    replayBuffer[0] = 0;
  }

  int DifficultyLevel() const override {
    return 1;
  }

  void OnCombinedMapReady() override {
    randomState = EnvironmentUnsigned("IMPERIALISM_RUNTIME_TEST_SEED", 1) ^ 0x9e3779b9UL;
    maxActions = static_cast<int>(
        EnvironmentUnsigned("IMPERIALISM_RUNTIME_EXPLORE_MAX_ACTIONS", 500));
    settleTicks = static_cast<int>(
        EnvironmentUnsigned("IMPERIALISM_RUNTIME_EXPLORE_SETTLE_TICKS", 2, true));
    if (settleTicks > 100) {
      settleTicks = 100;
    }
    actionCount = 0;
    cooldownTicks = 0;
    replayOffset = 0;
    replayMode = false;
    replayBuffer[0] = 0;

    InitializeArtifactPaths();
    if (!LoadReplayFile()) {
      FailScenario("\"could not read random-control replay\"");
      return;
    }
    if (!tracePath.IsEmpty()) {
      DeleteFileA(static_cast<LPCSTR>(tracePath));
    }
    EnterScenarioStep("exploring_random_controls",
                      replayMode ? "start_control_replay" : "start_random_control_exploration");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (cooldownTicks > 0) {
      --cooldownTicks;
      RequestScenarioTick();
      return;
    }

    CString path;
    int localX = 0;
    int localY = 0;
    TView* root = g_pDisplayMgr != 0 ? g_pDisplayMgr->activeDialog : 0;
    if (root == 0) {
      if (ScenarioPhaseElapsedMs() >= 2000) {
        Pass();
      } else {
        RequestScenarioTick();
      }
      return;
    }

    TView* view = 0;
    if (replayMode) {
      ReplayReadResult replay = ReadReplayAction(path, localX, localY);
      if (replay == kReplayEnd) {
        Pass();
        return;
      }
      if (replay == kReplayInvalid) {
        Pass();
        return;
      }
      view = ResolveViewPath(root, path);
      if (view == 0 || !view->IsActionable() || localX < 0 || localY < 0 ||
          localX >= view->frameWidth34 || localY >= view->frameHeight38) {
        Pass();
        return;
      }
    } else {
      if (actionCount >= maxActions) {
        Pass();
        return;
      }
      selectedView = 0;
      selectedPath.Empty();
      candidateCount = 0;
      SelectRandomActionableView(root, CString());
      view = selectedView;
      path = selectedPath;
      if (view == 0) {
        if (ScenarioPhaseElapsedMs() >= 2000) {
          Pass();
        } else {
          RequestScenarioTick();
        }
        return;
      }
      localX = RandomCoordinate(view->frameWidth34);
      localY = RandomCoordinate(view->frameHeight38);
    }

    CString action;
    action.Format("click_random_control_%d", actionCount);
    EnterScenarioStep("exploring_random_controls", static_cast<LPCSTR>(action));
    if (!AppendTrace(actionCount, path, view, localX, localY)) {
      FailScenario("\"could not persist random-control trace\"");
      return;
    }
    ++actionCount;
    if (!RuntimeUiDriver::ClickViewPointThroughNativeMessages(view, localX, localY)) {
      Pass();
      return;
    }
    cooldownTicks = settleTicks;
    RequestScenarioTick();
  }

private:
  unsigned long NextRandom() {
    randomState = randomState * 1664525UL + 1013904223UL;
    return randomState;
  }

  int RandomCoordinate(int extent) {
    if (extent <= 1) {
      return 0;
    }
    if (extent <= 4) {
      return extent / 2;
    }
    return 2 + static_cast<int>(NextRandom() % static_cast<unsigned long>(extent - 4));
  }

  void SelectRandomActionableView(TView* view, const CString& parentPath) {
    if (view == 0) {
      return;
    }
    CString path = ViewPath(view, parentPath);
    if (view->frameWidth34 > 0 && view->frameHeight38 > 0 && view->IsActionable()) {
      ++candidateCount;
      if (NextRandom() % static_cast<unsigned long>(candidateCount) == 0) {
        selectedView = view;
        selectedPath = path;
      }
    }
    if (view->childList44 == 0) {
      return;
    }
    POSITION position = view->childList44->GetHeadPosition();
    while (position != 0) {
      SelectRandomActionableView(view->childList44->GetNext(position), path);
    }
  }

  TView* FindChild(TView* parent, unsigned int tag, int occurrence) {
    if (parent == 0 || parent->childList44 == 0 || occurrence <= 0) {
      return 0;
    }
    int seen = 0;
    POSITION position = parent->childList44->GetHeadPosition();
    while (position != 0) {
      TView* child = parent->childList44->GetNext(position);
      if (static_cast<unsigned int>(child->controlTag) == tag && ++seen == occurrence) {
        return child;
      }
    }
    return 0;
  }

  bool ParsePathSegment(char* segment, unsigned int& tag, int& occurrence) {
    char* hash = strchr(segment, '#');
    if (hash == 0) {
      return false;
    }
    *hash = 0;
    char* tagEnd = 0;
    unsigned long parsedTag = strtoul(segment, &tagEnd, 16);
    char* occurrenceEnd = 0;
    long parsedOccurrence = strtol(hash + 1, &occurrenceEnd, 10);
    if (tagEnd == segment || *tagEnd != 0 || occurrenceEnd == hash + 1 ||
        *occurrenceEnd != 0 || parsedOccurrence <= 0) {
      return false;
    }
    tag = static_cast<unsigned int>(parsedTag);
    occurrence = static_cast<int>(parsedOccurrence);
    return true;
  }

  TView* ResolveViewPath(TView* root, const CString& path) {
    if (path.GetLength() >= 2048) {
      return 0;
    }
    char buffer[2048];
    lstrcpyA(buffer, static_cast<LPCSTR>(path));
    TView* current = root;
    char* segment = buffer;
    bool first = true;
    while (segment != 0 && *segment != 0) {
      char* slash = strchr(segment, '/');
      if (slash != 0) {
        *slash = 0;
      }
      unsigned int tag = 0;
      int occurrence = 0;
      if (!ParsePathSegment(segment, tag, occurrence)) {
        return 0;
      }
      if (first) {
        if (static_cast<unsigned int>(current->controlTag) != tag ||
            occurrence != TagOccurrenceBefore(current->ownerContext, current)) {
          return 0;
        }
        first = false;
      } else {
        current = FindChild(current, tag, occurrence);
        if (current == 0) {
          return 0;
        }
      }
      segment = slash != 0 ? slash + 1 : 0;
    }
    return first ? 0 : current;
  }

  ReplayReadResult ReadReplayAction(CString& path, int& localX, int& localY) {
    char* line = replayBuffer + replayOffset;
    if (*line == 0) {
      return kReplayEnd;
    }
    char* newline = strchr(line, '\n');
    if (newline != 0) {
      *newline = 0;
      replayOffset = static_cast<int>(newline - replayBuffer) + 1;
    } else {
      replayOffset = static_cast<int>(strlen(replayBuffer));
    }
    char* firstTab = strchr(line, '\t');
    if (firstTab == 0) {
      return kReplayInvalid;
    }
    *firstTab = 0;
    char* secondTab = strchr(firstTab + 1, '\t');
    if (secondTab == 0) {
      return kReplayInvalid;
    }
    *secondTab = 0;
    char* xEnd = 0;
    char* yEnd = 0;
    long parsedX = strtol(firstTab + 1, &xEnd, 10);
    long parsedY = strtol(secondTab + 1, &yEnd, 10);
    if (line[0] == 0 || xEnd == firstTab + 1 || *xEnd != 0 || yEnd == secondTab + 1 ||
        *yEnd != 0) {
      return kReplayInvalid;
    }
    path = line;
    localX = static_cast<int>(parsedX);
    localY = static_cast<int>(parsedY);
    return kReplayAction;
  }

  void InitializeArtifactPaths() {
    char resultPath[2048];
    DWORD length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_RESULT", resultPath,
                                           sizeof(resultPath));
    if (length == 0 || length >= sizeof(resultPath)) {
      tracePath = "exploration-trace.jsonl";
      replayPath = "exploration-replay.txt";
      return;
    }
    char* slash = strrchr(resultPath, '\\');
    char* forwardSlash = strrchr(resultPath, '/');
    if (forwardSlash != 0 && (slash == 0 || forwardSlash > slash)) {
      slash = forwardSlash;
    }
    if (slash == 0) {
      tracePath = "exploration-trace.jsonl";
      replayPath = "exploration-replay.txt";
      return;
    }
    slash[1] = 0;
    CString directory(resultPath);
    tracePath = directory + "exploration-trace.jsonl";
    replayPath = directory + "exploration-replay.txt";
  }

  bool LoadReplayFile() {
    HANDLE file = CreateFileA(static_cast<LPCSTR>(replayPath), GENERIC_READ, FILE_SHARE_READ, 0,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
      return GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    DWORD size = GetFileSize(file, 0);
    if (size == INVALID_FILE_SIZE || size >= sizeof(replayBuffer)) {
      CloseHandle(file);
      return false;
    }
    DWORD read = 0;
    BOOL ok = ReadFile(file, replayBuffer, size, &read, 0);
    CloseHandle(file);
    if (!ok || read != size) {
      replayBuffer[0] = 0;
      return false;
    }
    replayBuffer[read] = 0;
    replayMode = true;
    return true;
  }

  bool AppendTrace(int index, const CString& path, TView* view, int localX, int localY) {
    if (tracePath.IsEmpty()) {
      return false;
    }
    CString line;
    CString prefix;
    prefix.Format("{\"index\":%d,\"path\":", index);
    line += prefix;
    RuntimeJson::AppendString(line, static_cast<LPCSTR>(path));
    CString fields;
    CString tag;
    tag.Format("%08x", static_cast<unsigned int>(view->controlTag));
    line += ",\"tag\":";
    RuntimeJson::AppendString(line, static_cast<LPCSTR>(tag));
    line += ",\"class\":";
    RuntimeJson::AppendString(line, RuntimeClassName(view));
    fields.Format(",\"event\":%d,\"local_x\":%d,\"local_y\":%d}", view->GetEventNumber(),
                  localX, localY);
    line += fields;
    line += "\r\n";

    HANDLE file = CreateFileA(static_cast<LPCSTR>(tracePath), GENERIC_WRITE, FILE_SHARE_READ, 0,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
      return false;
    }
    SetFilePointer(file, 0, 0, FILE_END);
    DWORD written = 0;
    BOOL ok = WriteFile(file, static_cast<LPCSTR>(line), line.GetLength(), &written, 0);
    if (ok) {
      ok = FlushFileBuffers(file);
    }
    CloseHandle(file);
    return ok != 0 && written == static_cast<DWORD>(line.GetLength());
  }

  unsigned long randomState;
  int actionCount;
  int maxActions;
  int settleTicks;
  int cooldownTicks;
  int replayOffset;
  bool replayMode;
  char replayBuffer[250000];
  CString tracePath;
  CString replayPath;
  TView* selectedView;
  CString selectedPath;
  int candidateCount;
};

RandomControlExplorerTestCase g_test;

} // namespace

RuntimeTestCase* RandomControlExplorerTest() {
  return &g_test;
}
