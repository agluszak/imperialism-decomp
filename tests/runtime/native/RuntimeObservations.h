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
void CaptureRuntimeMapState(RuntimeRun& run);
bool VerifyRuntimeStrategicCoastCornerComposite(TMapDialog* mapDialog);
bool VerifyRuntimeMiniMapViewportFrame(TMiniMapView* miniMap);
bool CaptureRuntimePrimarySurfaceBmp(const char* resultPath);
bool CaptureRuntimeWindowBmp(const char* resultPath, HWND window, int width, int height);
