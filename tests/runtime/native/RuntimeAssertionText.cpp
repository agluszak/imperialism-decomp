#include "RuntimeAssertionText.h"

#include "RuntimeHarnessCore.h"
#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeRun.h"

#include "game/core/global_data_tables.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/view_registries.h"

namespace {

// The block every failure gets. Reading a runtime failure without knowing which screen was
// up and whether a modal was covering it is guesswork, and these four facts are the ones
// that decide where to look next.
CString ContextBlock(const RuntimeRun& run, const char* file, int line) {
  CString block;
  CString source;
  if (file != 0 && file[0] != 0) {
    source.Format("%s:%d", RuntimeSourceBasename(file), line);
  } else {
    source = "unknown";
  }
  char awaited[256];
  const RuntimeAwaitState& await = run.AwaitState();
  block.Format("source: %s\nphase: %s\ncurrent event: 0x%04x\ncurrent view: %s\nmodal depth: %d",
               static_cast<LPCSTR>(source), run.PhaseName(),
               g_pViewMgr != 0 ? static_cast<unsigned int>(g_pViewMgr->currentTurnEventCode) : 0u,
               RuntimeClassName(RuntimeMainView()), g_ModalViewStack.GetCount());
  // A failure raised while a wait was armed usually means the wait's condition and the
  // assertion disagree, so name the wait too.
  if (await.IsArmed()) {
    DescribeRuntimeObservationMask(await.ObservationKinds(), awaited, sizeof(awaited));
    CString waiting;
    waiting.Format("\nawaiting: %s\nawaiting observations: %s", await.Expression(), awaited);
    block += waiting;
  }
  return block;
}

} // namespace

namespace RuntimeAssertionText {

CString Requirement(const RuntimeRun& run, const char* expression, const char* file, int line) {
  CString text;
  text.Format("requirement: %s\n%s", expression != 0 ? expression : "",
              static_cast<LPCSTR>(ContextBlock(run, file, line)));
  return text;
}

CString RequirementValues(const RuntimeRun& run, const char* expression, const char* relation,
                          const CString& expected, const CString& actual, const char* file,
                          int line) {
  CString text;
  text.Format("requirement: %s\nrelation: %s\nexpected: %s\nactual: %s\n%s",
              expression != 0 ? expression : "", relation != 0 ? relation : "",
              static_cast<LPCSTR>(expected), static_cast<LPCSTR>(actual),
              static_cast<LPCSTR>(ContextBlock(run, file, line)));
  return text;
}

CString Failure(const RuntimeRun& run, const char* failureText, const char* file, int line) {
  CString text;
  text.Format("%s\n%s", failureText != 0 ? failureText : "",
              static_cast<LPCSTR>(ContextBlock(run, file, line)));
  return text;
}

CString RequirementJson(const RuntimeRun& run, const char* expression, const char* file, int line) {
  CString json;
  RuntimeJson::AppendString(json, static_cast<LPCSTR>(Requirement(run, expression, file, line)));
  return json;
}

const char* PhaseSlug(const char* text) {
  // Static because the callers hand the result straight to EnterPhase/RecordAssertion, which
  // copy into their own fixed buffers before anything else can call this again.
  static char slug[64];
  unsigned long length = 0;
  bool pendingSeparator = false;
  for (const char* cursor = text != 0 ? text : ""; *cursor != 0; ++cursor) {
    char character = *cursor;
    bool isDigit = character >= '0' && character <= '9';
    bool isLower = character >= 'a' && character <= 'z';
    bool isUpper = character >= 'A' && character <= 'Z';
    if (!isDigit && !isLower && !isUpper) {
      // Collapse every run of punctuation or space into a single underscore, and never lead
      // with one.
      pendingSeparator = length != 0;
      continue;
    }
    if (length + (pendingSeparator ? 1u : 0u) + 1 >= sizeof(slug)) {
      break;
    }
    if (pendingSeparator) {
      slug[length++] = '_';
      pendingSeparator = false;
    }
    slug[length++] = isUpper ? static_cast<char>(character - 'A' + 'a') : character;
  }
  slug[length] = 0;
  if (length == 0) {
    lstrcpyA(slug, "step");
  }
  return slug;
}

CString Value(int value) {
  CString text;
  text.Format("%d", value);
  return text;
}

CString Value(unsigned int value) {
  CString text;
  // Hex alongside decimal, because unsigned scenario values are usually tags or masks.
  text.Format("%u (0x%x)", value, value);
  return text;
}

CString Value(short value) {
  CString text;
  text.Format("%d", static_cast<int>(value));
  return text;
}

CString Value(unsigned short value) {
  CString text;
  text.Format("%u", static_cast<unsigned int>(value));
  return text;
}

CString Value(long value) {
  CString text;
  text.Format("%ld", value);
  return text;
}

CString Value(unsigned long value) {
  CString text;
  text.Format("%lu (0x%lx)", value, value);
  return text;
}

CString Value(bool value) {
  return CString(value ? "true" : "false");
}

CString Value(const void* value) {
  CString text;
  if (value == 0) {
    return CString("null");
  }
  text.Format("%p", value);
  return text;
}

CString Value(const char* value) {
  CString text;
  if (value == 0) {
    return CString("null");
  }
  text.Format("\"%s\"", value);
  return text;
}

CString Value(const CString& value) {
  CString text;
  text.Format("\"%s\"", static_cast<LPCSTR>(value));
  return text;
}

} // namespace RuntimeAssertionText
