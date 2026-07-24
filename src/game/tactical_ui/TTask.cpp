#include "game/tactical_ui/TTask.h"
#include "game/core/TStream.h"
// SYNTHETIC: IMPERIALISM 0x005adb40
// TTask::CreateObject

// SYNTHETIC: IMPERIALISM 0x005adb70
// TTask::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTask, TObject)

// NOOP: verified empty in original 0x005adb42 (no standalone TTask::TTask body exists: construction is fully inlined into CreateObject 0x005adb40; that address is its operator-new call site)
TTask::TTask() {}

// SYNTHETIC: IMPERIALISM 0x005adbb0
// TTask::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005adbe0
TTask::~TTask() {}

// FUNCTION: IMPERIALISM 0x005adc30
bool TTask::Tick(TSortedList*) {
  return --remainingAttempts == 0;
}

// FUNCTION: IMPERIALISM 0x005adc50
void TTask::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&citySlotIndex, 2);
  stream->WriteBytesSlot78(&remainingAttempts, 2);
}

// FUNCTION: IMPERIALISM 0x005adc90
void TTask::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&citySlotIndex, 2);
  stream->ReadBytes(&remainingAttempts, 2);
}
