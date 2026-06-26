#pragma once

#include "game/mfc.h"

struct BufferedStreamState {
  unsigned char* cursor;
  int bytesAvailable;
  unsigned char* buffer;
  unsigned int flags;
  HANDLE fileHandle;
  int field14;
  int bufferSize;
  int field1c;
  CRITICAL_SECTION criticalSection;
};

BufferedStreamState* OpenBufferedStreamWithMode40(const char* path, const char* mode);
void ReadLineFromBufferedStreamUntilTerminator(char* outLine, int maxLength,
                                               BufferedStreamState* stream);
int ReadNextByteFromBufferedStreamWithLock(BufferedStreamState* stream);
int CloseBufferedStreamAndReleaseResources(BufferedStreamState* stream);
int ParseSignedIntFromAsciiWithWhitespaceSkip(char* text);
int ParseSignedIntAndDiscardResult(char* text);
