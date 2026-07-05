#include "game/TMiniMapView.h"

#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x0059a290
// TMiniMapView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059a360
// TMiniMapView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniMapView, TControl)

// FUNCTION: IMPERIALISM 0x0059a380
TMiniMapView::TMiniMapView()
    : TControl(), ownerPicture84(nullptr), scrollTileColumn88(0), scrollTileRow8c(0),
      markerBoxX90(0), markerBoxY94(0), markerBoxWidth98(g_defaultMarkerBoxWidth_006a460c),
      markerBoxHeight9c(8) {}

// SYNTHETIC: IMPERIALISM 0x0059a3f0
// TMiniMapView::`scalar deleting destructor'
TMiniMapView::~TMiniMapView() {}

// FUNCTION: IMPERIALISM 0x0059a540
void TMiniMapView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x0059a920
void TMiniMapView::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                  void* pEventDataA, void* pEventDataB) {}
