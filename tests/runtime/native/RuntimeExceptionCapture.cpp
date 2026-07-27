#include "RuntimeExceptionCapture.h"

#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeResultWriter.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"

#include "game/core/global_data_tables.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

#include <windows.h>

namespace {

RuntimeRun* g_exceptionRun = 0;
RuntimeScenario* g_exceptionScenario = 0;

LONG WINAPI RuntimeUnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
  if (g_exceptionRun != 0 && g_exceptionScenario != 0 && !g_exceptionRun->IsFinished() &&
      info != 0 && info->ExceptionRecord != 0) {
    g_exceptionRun->RecordAssertion("process.unhandled_exception", "\"unhandled exception\"", true);
    RuntimeExceptionCapture::Trap(*g_exceptionRun, *g_exceptionScenario,
                                  kRuntimeDebugUnhandledException, "\"unhandled exception\"", info);
    CString fault;
    fault.Format("{\"code\": \"0x%08lx\", \"address\": \"%p\", \"phase\": \"%s\", "
                 "\"last_action\": \"%s\"}",
                 info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress,
                 g_exceptionRun->PhaseName(), g_exceptionRun->LastAction());
    RuntimeJson::AppendArrayItem(g_exceptionRun->Faults(), fault);
    g_exceptionRun->Finish();
    WriteRuntimeResult(*g_exceptionRun, *g_exceptionScenario, "failed", "\"unhandled exception\"");
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

void RuntimeExceptionCapture::Install(RuntimeRun& run, RuntimeScenario& scenario) {
  g_exceptionRun = &run;
  g_exceptionScenario = &scenario;
  SetUnhandledExceptionFilter(RuntimeUnhandledExceptionFilter);
}

void RuntimeExceptionCapture::Trap(RuntimeRun& run, RuntimeScenario& scenario,
                                   RuntimeDebugReason reason, const char* failureJson,
                                   EXCEPTION_POINTERS* exception) {
  TView* activeModal =
      g_ModalViewStack.IsEmpty() ? 0 : static_cast<TView*>(g_ModalViewStack.GetHead());
  RuntimeDebugRecord record;
  record.reason = reason;
  record.elapsedMs = run.ElapsedMs();
  record.testName = run.TestName();
  record.phase = run.PhaseName();
  record.lastAction = run.LastAction();
  record.turnEvent = g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1;
  record.modalDepth = g_ModalViewStack.GetCount();
  record.mainView = RuntimeMainView();
  record.activeModal = activeModal;
  record.simMgr = g_pSimMgr;
  record.exceptionPointers = exception;

  if (run.DebugRecordPath()[0] != 0) {
    CString exceptionJson("null");
    if (exception != 0 && exception->ExceptionRecord != 0) {
      exceptionJson.Format("{\"code\": \"0x%08lx\", \"address\": \"%p\"}",
                           exception->ExceptionRecord->ExceptionCode,
                           exception->ExceptionRecord->ExceptionAddress);
    }
    CString json;
    json.Format("{\"reason\": %d, \"test\": \"%s\", \"phase\": \"%s\", "
                "\"last_action\": \"%s\", \"elapsed_ms\": %lu, \"turn_event\": %d, "
                "\"modal_depth\": %d, \"assertion_id\": \"%s\", \"failure\": %s, "
                "\"exception\": %s}\n",
                static_cast<int>(reason), run.TestName(), run.PhaseName(), run.LastAction(),
                record.elapsedMs, record.turnEvent, record.modalDepth, run.FirstAssertionId(),
                failureJson, static_cast<LPCSTR>(exceptionJson));
    RuntimeJson::WriteFileAtomically(run.DebugRecordPath(), json);
  }
  ImperialismRuntimeDebuggerTrap(&record);
}
