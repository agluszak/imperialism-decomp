#pragma once

#include "decomp_types.h"

// MFC-style serialization stream hierarchy (TStream family). Each concrete
// stream installs its own vtable and is reset to the shared CObject runtime
// vtable on teardown.

struct TFileStream {
  void* vftable;
  void* field04;

  static void* GetTFileStreamClassNamePointer();
  TFileStream* ConstructTFileStreamBaseState();
  void* DestructTFileStreamAndMaybeFree(byte freeSelfFlag);
};

struct TCountingStream {
  void* vftable;
  void* field04;
  void* field08;

  static void* GetTCountingStreamClassNamePointer();
  TCountingStream* ConstructTCountingStreamBaseState();
  void DestructTCountingStreamBaseState();
  void* DestructTCountingStreamAndMaybeFree(byte freeSelfFlag);
};

struct THandleStream {
  void* vftable;
  void* field04;
  void* field08;
  void* field0c;
  int field10;
  byte field14;

  static void* GetTHandleStreamClassNamePointer();
  THandleStream* ConstructTHandleStreamBaseState();
  void DestructTHandleStreamBaseState();
  void* DestructTHandleStreamAndMaybeFree(byte freeSelfFlag);
};
