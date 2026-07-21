#include "game/TClickZone.h"

// FUNCTION: IMPERIALISM 0x005723d0
void TClickZone::Hilite() {}
// SYNTHETIC: IMPERIALISM 0x00572350
// TClickZone::CreateObject

// SYNTHETIC: IMPERIALISM 0x005723f0
// TClickZone::GetRuntimeClass

IMPLEMENT_DYNCREATE(TClickZone, TControl)

// FUNCTION: IMPERIALISM 0x00572410
TClickZone::TClickZone() : TControl(), clickSoundId84(0x1b58) {}

// SYNTHETIC: IMPERIALISM 0x00572440
// TClickZone::`scalar deleting destructor'
TClickZone::~TClickZone() {}

// FUNCTION: IMPERIALISM 0x00572490
void TClickZone::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point, TToolboxEvent* event,
                                                      CPoint origin) {}
