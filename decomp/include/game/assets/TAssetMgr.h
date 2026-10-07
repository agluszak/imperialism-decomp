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
  virtual ~TAssetMgr() override; // slot 0x01 (scalar deleting destructor)
  virtual TWindow*
  ResolveTurnEventDialogNodeByMessageContext(TurnEventId messageContext); // slot 0x0a 0x5df3c0
  virtual void OpenFilesForView(short fileSet);                           // slot 0x0b 0x5df780
  virtual void OpenFilesFor(short fileSet);                               // slot 0x0c 0x5df3f0
  virtual void CloseFilesFor(short fileSet);                              // slot 0x0d 0x5df410
  // The third argument is unused by the Windows body but is part of the retail virtual ABI:
  // the caller pushes it before the movie-view and CString-reference arguments, and the callee
  // returns with RET 0x0c.
  virtual void PlayMovieClipAndDispatchTurnStateFollowup(const CString& movieName,
                                                         TMovieView* movieView,
                                                         int unused); // slot 0x0e 0x5dfc10

  void GetScenarioFileName(int scenarioIndex, int mode, CString* outPath);
  CFile* LoadTableResourceStreamByName(CString name);
  int ReadResourceStreamIntoBufferAndAdvance(CFile* stream, void* buffer, int* countInOut);
  void ReleaseResourceStreamIfNotNull(CFile* stream); // 0x5df6d0
  // Reseek the stream from the start; `this` is unused. 0x5df730.
  void SeekResourceStreamFromBeginning(CFile* stream, int offset);
  // Thiscall member that ignores `this` and returns the stream's length.
  int GetResourceStreamSize(CFile* stream); // 0x5df760

  int unusedRegion[7];
  CString sharedTextSlots[0xd]; // +0x20 .. 0x54
  int deadStore54;              // +0x54

  TAssetMgr();
  void EnsurePictWvDataGobLoadedBySlot(int languageTag);
  void ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag);
  unsigned char SaveMainDocumentToPathAndMarkSaved(const CString& savePath);
  bool OpenMainDocumentFromPathAndMarkLoaded(const CString& loadPath);
  void SetPreferenceString(CString* value, const char* key);
  void LoadSettingValueByKeyIntoOut(int* out, LPCSTR key, int defaultValue);
  void SetPreferenceInt(int value, LPCSTR key); // 0x005e02c0
  bool AreThereStrayClientSaves();
  int DeleteStrayClientSaves();
  void ScheduleTimerSlotCallbackWithInterval(TimerSlotCallback callback, UINT interval, int slot);
  CString FormatVersionStringFromVersionResource();
};

void __stdcall AssignScoresDatPathToSharedString(CString* out);
