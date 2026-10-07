#pragma once

#include "game/core/CString.h"
#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/assets/timer_slots.h"
#include "game/turn_event_codes.h"

class TView;
class TWindow;
class TMovieView;

// VTABLE: IMPERIALISM 0x0066f508
class TAssetMgr : public TObject {
public:
  DECLARE_DYNCREATE(TAssetMgr)
  virtual ~TAssetMgr() override;
  virtual TWindow* ResolveTurnEventDialogNodeByMessageContext(TurnEventId messageContext);
  virtual void OpenFilesForView(short fileSet);
  virtual void OpenFilesFor(short fileSet);
  virtual void CloseFilesFor(short fileSet);
  // ABI: the third argument is unused but still pushed by callers (RET 0x0c).
  virtual void OpenMovie(const CString& movieName, TMovieView* movieView, int unused);

  void GetScenarioFileName(int scenarioIndex, int mode, CString* outPath);
  CFile* LoadTableResourceStreamByName(CString name);
  int ReadResourceStreamIntoBufferAndAdvance(CFile* stream, void* buffer, int* countInOut);
  void ReleaseResourceStreamIfNotNull(CFile* stream);
  // Reseek the stream from the start; `this` is unused.
  void SeekResourceStreamFromBeginning(CFile* stream, int offset);
  // Thiscall member that ignores `this` and returns the stream's length.
  int GetResourceStreamSize(CFile* stream);

  int unusedRegion[7];
  CString sharedTextSlots[13];
  int deadStore54;

  TAssetMgr();
  void EnsurePictWvDataGobLoadedBySlot(int languageTag);
  void ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag);
  unsigned char SaveTheGame(const CString& savePath);
  bool LoadTheGame(const CString& loadPath);
  void SetPreferenceString(CString* value, const char* key);
  void GetPreferenceInt(int* out, LPCSTR key, int defaultValue);
  void SetPreferenceInt(int value, LPCSTR key);
  bool AreThereStrayClientSaves();
  int DeleteStrayClientSaves();
  void ScheduleTimerSlotCallbackWithInterval(TimerSlotCallback callback, UINT interval, int slot);
  CString FormatVersionStringFromVersionResource();
};

void __stdcall AssignScoresDatPathToSharedString(CString* out);
