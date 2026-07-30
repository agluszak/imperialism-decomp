#include "RuntimeAssertionText.h"

#include "RuntimeHarnessCore.h"
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
