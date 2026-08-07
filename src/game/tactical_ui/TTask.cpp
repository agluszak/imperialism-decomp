#include "game/tactical_ui/TTask.h"
#include "game/core/TStream.h"
// SYNTHETIC: IMPERIALISM 0x005adb40
// TTask::CreateObject

// SYNTHETIC: IMPERIALISM 0x005adb70
// TTask::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTask, TObject)

// FUNCTION: IMPERIALISM 0x005adb90
TTask::TTask() {}

// SYNTHETIC: IMPERIALISM 0x005adbb0
// TTask::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005adc00
void TTask::ITask(short citySlotType) {
  remainingAttempts = 4;
  citySlotIndex = citySlotType;
}

// FUNCTION: IMPERIALISM 0x005adc30
bool TTask::Execute(TTaskList*) {
  return --remainingAttempts == 0;
}

// FUNCTION: IMPERIALISM 0x005adc50
void TTask::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&citySlotIndex, 2);
  stream->WriteBytes(&remainingAttempts, 2);
}

// FUNCTION: IMPERIALISM 0x005adc90
void TTask::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&citySlotIndex, 2);
  stream->ReadBytes(&remainingAttempts, 2);
}
