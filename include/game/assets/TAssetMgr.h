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
  // Retail Mac identities. These are real resource-file lifecycle slots even though
  // the Windows implementations are intentional no-ops.
  virtual void OpenFilesForView(short fileSet); // slot 0x0b 0x5df780
  virtual void OpenFilesFor(short fileSet);     // slot 0x0c 0x5df3f0
  virtual void CloseFilesFor(short fileSet);    // slot 0x0d 0x5df410
  // The third argument is unused by the Windows body but is part of the retail virtual ABI:
  // the caller pushes it before the movie-view and CString-reference arguments, and the callee
  // returns with RET 0x0c.
  virtual void PlayMovieClipAndDispatchTurnStateFollowup(const CString& movieName,
                                                         TMovieView* movieView,
                                                         int unused); // slot 0x0e 0x5dfc10

  // Non-virtual resource-stream helpers (every call site loads ECX = g_pAssetMgr;
  // the callees ignore `this`). Used by the battle-setup .tab loader (0x5a4fc0).
  // Compose the on-disk path for a scenario table resource (mode 1 = map state) into
  // outPath. 0x5dfd70; `this` ignored (same singleton idiom as the siblings below).
  void BuildScenarioPathForModeAndIndex(int scenarioIndex, int mode, CString* outPath);
  // Finds "name" as a TABLE resource in the app's own module; if present, loads it and
  // returns a CMemFile attached to the locked resource bytes. If absent, falls back to
  // opening "name" as a real disk file via a plain CFile (asserting on failure unless
  // the file's own suppress flag is set). Both concrete objects use the real MFC CFile
  // virtual interface. 0x5df430.
  CFile* LoadTableResourceStreamByName(CString name);
  // Reads *countInOut bytes from the stream into buffer, writes bytes-read back
  // through countInOut. 0x5df700.
  int ReadResourceStreamIntoBufferAndAdvance(CFile* stream, void* buffer, int* countInOut);
  void ReleaseResourceStreamIfNotNull(CFile* stream); // 0x5df6d0
  // Reseek the stream from the start; `this` is unused. 0x5df730.
  void SeekResourceStreamFromBeginning(CFile* stream, int offset);
  // Thiscall member that ignores `this` and returns the stream's length.
  int GetResourceStreamSize(CFile* stream); // 0x5df760

  // Layout recovered from ctor 0x5df280: the 13 shared UI string-reference slots live at
  // offset 0x20, preceded by an as-yet-unidentified 0x1c-byte region and followed by one
  // trailing word; sizeof(TAssetMgr) per RTTI is 0x58. The ctor default-constructs all 13
  // entries via the EH array-construct helper; the scalar deleting dtor (0x5df300) tears
  // them down with the matching array-destroy helper.
  // +0x04..+0x20: no access anywhere. A field-xref sweep at each of the seven dword
  // offsets returns zero reads and zero writes, so this is not an unrecovered layout --
  // nothing in the shipped binary touches it.
  int unusedRegion04[7];
  CString sharedTextSlots[0xd]; // +0x20 .. 0x54
  int unknown54;                // +0x54

  TAssetMgr();
  // 0x5dff20 — load the picture-word-data GOB for a language slot. Real __thiscall
  // whose body ignores `this` (previously mis-modelled as a free __stdcall, which
  // dropped the ECX load at call sites). Outside callers dispatch through
  // g_pAssetMgr; sibling TAssetMgr methods (Forward…, …ForLanguageSlot) pass
  // their own `this` straight through.
  void EnsurePictWvDataGobLoadedBySlot(int languageTag);
  // 0x5df3a0 — thiscall passthrough forwarder: calls EnsurePict…BySlot(0), reusing the
  // incoming `this` in ECX (no reload). Ignores its languageTag argument.
  void ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag);
  // Save the MFC document to `savePath`, then restamp its path with the "__saved"
  // marker so later saves re-prompt. `this` is unused; callers still dispatch it
  // through g_pAssetMgr. 0x005e0030.
  unsigned char SaveMainDocumentToPathAndMarkSaved(const CString& savePath);
  // Open the MFC document from `loadPath` (CWinApp::OpenDocumentFile) and restamp its
  // path with the "__loaded" marker; returns whether a document was opened. `this` is
  // unused; callers dispatch through g_pAssetMgr. 0x005e0150.
  unsigned char OpenMainDocumentFromPathAndMarkLoaded(const CString& loadPath);
  // Writes *value under key in the application's "Settings" profile section. `this`
  // is unused, but all retail callsites dispatch through g_pAssetMgr. 0x5e0260.
  void SaveSettingValueFromPointerByKey(CString* value, const char* key);
  // CWinApp::GetProfileInt(key, defaultValue) under the "Settings" section, stored
  // into *out. `this` is unused; callers dispatch through g_pAssetMgr. 0x5e0290.
  // Parameter order verified from the 0x5e0290 listing: the OUT pointer is the first
  // argument ([esp+4] receives the GetProfileInt result), then key, then default.
  void LoadSettingValueByKeyIntoOut(int* out, LPCSTR key, int defaultValue);
  void WriteIntegerSettingByValueAndKey(int value, LPCSTR key); // 0x005e02c0
  // Checks for a pending "save/cli_*.imp" client save file (resumable multiplayer
  // session). `this` is unused; callers dispatch through g_pAssetMgr. 0x5e02f0.
  unsigned char HasPendingClientSaveFile();
  // Deletes every "save/cli_*.imp" legacy client save file, returning the count
  // removed. `this` is unused; callers dispatch through g_pAssetMgr. 0x5e0340.
  int DeleteLegacyCliSaveImpFiles();
  // Register an audio-state callback in the shared slot table and arm its Win32 timer.
  // Every caller loads ECX = g_pAssetMgr even though the body does not read `this`.
  // 0x005e0520.
  void ScheduleTimerSlotCallbackWithInterval(TimerSlotCallback callback, UINT interval, int slot);
  // Loads the module's RT_VERSION resource and formats "(v. major.minor[.build[.revision]])"
  // from its VS_FIXEDFILEINFO dwFileVersionMS/dwFileVersionLS fields in the loaded resource
  // block, matching the original's direct FindResource/LoadResource parse rather than
  // VerQueryValue. `this` is unused; callers dispatch through g_pAssetMgr. 0x5e0590.
  CString FormatVersionStringFromVersionResource();
};

void __stdcall AssignScoresDatPathToSharedString(CString* out);
