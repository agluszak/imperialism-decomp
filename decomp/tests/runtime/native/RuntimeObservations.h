#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeObservations is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

class RuntimeRun;
class TMapDialog;
class TMiniMapView;
class TView;
struct CRuntimeClass;

TView* RuntimeMainView();
const char* RuntimeClassName(TView* view);
bool RuntimeIsViewKindOf(TView* view, CRuntimeClass* runtimeClass);
CString CaptureRuntimeUiSnapshot(int eventCode, TView* root);
// Every tree reachable right now: the main view, plus each modal on g_ModalViewStack from
// the head down. Written into the result file whenever a run does not pass, because a
// selector that failed to resolve is exactly when an author needs to see the real tag
// hierarchy instead of guessing it from a UI builder. `just runtime-tree` prints it.
CString CaptureRuntimeCurrentUiTree();
void CaptureRuntimeMapState(RuntimeRun& run);
bool VerifyRuntimeStrategicCoastCornerComposite(TMapDialog* mapDialog);
bool VerifyRuntimeMiniMapViewportFrame(TMiniMapView* miniMap);
bool CaptureRuntimePrimarySurfaceBmp(const char* resultPath);
bool CaptureRuntimeWindowBmp(const char* resultPath, HWND window, int width, int height);
