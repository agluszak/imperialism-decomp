#include "game/buffered_stream.h"

#include <cstring>

namespace {
const int kBufferedStreamSlotCount = 20;
const int kDefaultBufferSize = 0x1000;
const unsigned int kFlagRead = 0x01;
const unsigned int kFlagWrite = 0x02;
const unsigned int kFlagOwnedBuffer = 0x08;
const unsigned int kFlagEndOfFile = 0x10;
const unsigned int kFlagError = 0x20;
const unsigned int kFlagCallerOwned = 0x40;
const unsigned int kFlagText = 0x4000;
const unsigned int kFlagBinary = 0x8000;

BufferedStreamState* g_bufferedStreamSlots[kBufferedStreamSlotCount];
CRITICAL_SECTION g_bufferedStreamTableLock;
bool g_bufferedStreamTableLockInitialized;

void EnsureBufferedStreamTableLockInitialized() {
  if (!g_bufferedStreamTableLockInitialized) {
    InitializeCriticalSection(&g_bufferedStreamTableLock);
    g_bufferedStreamTableLockInitialized = true;
  }
}

} // namespace

int ReadFromFileDescriptorWithLock(HANDLE fileHandle, void* buffer, unsigned int byteCount);
int CloseFileDescriptorWithLock(HANDLE fileHandle);
int FlushBufferedStreamPendingWrite(BufferedStreamState* stream);
int ReadBufferedStreamCoreUnlocked(void* destination, unsigned int elementSize,
                                   unsigned int elementCount, BufferedStreamState* stream);
void WrapperFor_FreeHeapBlockWithAllocatorTracking_At005efe50(BufferedStreamState* stream);
BufferedStreamState* FlushCloseAndResetBufferedStream(BufferedStreamState* stream);
BufferedStreamState* OpenBufferedStreamDescriptorWithModeAndLock(const char* path, const char* mode,
                                                                 unsigned int flags);
BufferedStreamState* OpenFileByModeStringAndInitStreamState(const char* path, const char* mode,
                                                            unsigned int streamFlags,
                                                            BufferedStreamState* stream);
BufferedStreamState* AcquireAndInitializeBufferedStreamSlot();
int RefillBufferedFileStreamAndReadFirstByte(BufferedStreamState* stream);
void EnterStreamCriticalSection(BufferedStreamState* stream);
void LeaveStreamCriticalSection(BufferedStreamState* stream);

// FUNCTION: IMPERIALISM 0x005d4ba0
void ReadLineFromBufferedStreamUntilTerminator(char* outLine, int maxLength,
                                               BufferedStreamState* stream) {
  int count = 0;
  if (maxLength <= 0) {
    return;
  }

  while ((stream->flags & kFlagEndOfFile) == 0) {
    const char value = static_cast<char>(ReadNextByteFromBufferedStreamWithLock(stream));
    *outLine = value;
    if (value == '\n' || value == '\r' || value == '\0') {
      *outLine = '\0';
      return;
    }

    ++outLine;
    ++count;
    if (maxLength <= count) {
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005e8760
int ParseSignedIntFromAsciiWithWhitespaceSkip(char* text) {
  while (*text == ' ' || *text == '\t' || *text == '\n' || *text == '\r') {
    ++text;
  }

  const bool negative = *text == '-';
  if (*text == '-' || *text == '+') {
    ++text;
  }

  int value = 0;
  while (*text >= '0' && *text <= '9') {
    value = value * 10 + (*text - '0');
    ++text;
  }

  if (negative) {
    value = -value;
  }
  return value;
}

// FUNCTION: IMPERIALISM 0x005e8800
int ParseSignedIntAndDiscardResult(char* text) {
  return ParseSignedIntFromAsciiWithWhitespaceSkip(text);
}

// FUNCTION: IMPERIALISM 0x005e9010
int CloseBufferedStreamAndReleaseResources(BufferedStreamState* stream) {
  if ((stream->flags & kFlagCallerOwned) != 0) {
    stream->flags = 0;
    return -1;
  }

  EnterStreamCriticalSection(stream);
  BufferedStreamState* closedStream = FlushCloseAndResetBufferedStream(stream);
  LeaveStreamCriticalSection(stream);
  return closedStream == 0 ? -1 : 0;
}

// FUNCTION: IMPERIALISM 0x005e9050
BufferedStreamState* FlushCloseAndResetBufferedStream(BufferedStreamState* stream) {
  BufferedStreamState* result = 0;
  if ((stream->flags & 0x83) != 0) {
    if (FlushBufferedStreamPendingWrite(stream) == 0) {
      result = stream;
    }
    WrapperFor_FreeHeapBlockWithAllocatorTracking_At005efe50(stream);
    if (CloseFileDescriptorWithLock(stream->fileHandle) < 0) {
      stream->flags = 0;
      return 0;
    }
    if (stream->field1c != 0) {
      stream->field1c = 0;
    }
  }
  stream->flags = 0;
  return result;
}

// FUNCTION: IMPERIALISM 0x005e90c0
BufferedStreamState* OpenBufferedStreamDescriptorWithModeAndLock(const char* path, const char* mode,
                                                                 unsigned int flags) {
  BufferedStreamState* stream = AcquireAndInitializeBufferedStreamSlot();
  if (stream == 0) {
    return 0;
  }

  BufferedStreamState* openedStream =
      OpenFileByModeStringAndInitStreamState(path, mode, flags, stream);
  LeaveStreamCriticalSection(stream);
  return openedStream;
}

// FUNCTION: IMPERIALISM 0x005e9100
BufferedStreamState* OpenBufferedStreamWithMode40(const char* path, const char* mode) {
  return OpenBufferedStreamDescriptorWithModeAndLock(path, mode, kFlagCallerOwned);
}

// FUNCTION: IMPERIALISM 0x005e9440
int ReadBufferedStreamLocked(void* destination, unsigned int elementSize, unsigned int elementCount,
                             BufferedStreamState* stream) {
  EnterStreamCriticalSection(stream);
  const int result = ReadBufferedStreamCoreUnlocked(destination, elementSize, elementCount, stream);
  LeaveStreamCriticalSection(stream);
  return result;
}

// FUNCTION: IMPERIALISM 0x005e9480
int ReadBufferedStreamCoreUnlocked(void* destination, unsigned int elementSize,
                                   unsigned int elementCount, BufferedStreamState* stream) {
  unsigned int remaining = elementSize * elementCount;
  const unsigned int requested = remaining;
  unsigned char* out = static_cast<unsigned char*>(destination);

  if (remaining == 0) {
    return 0;
  }

  unsigned int chunkSize = kDefaultBufferSize;
  if ((stream->flags & 0x10c) != 0) {
    chunkSize = stream->bufferSize;
  }

  while (remaining != 0) {
    int consumed = 0;
    if ((stream->flags & 0x10c) == 0 || stream->bytesAvailable == 0) {
      if (remaining < chunkSize) {
        const int value = RefillBufferedFileStreamAndReadFirstByte(stream);
        if (value == -1) {
          return (requested - remaining) / elementSize;
        }
        *out++ = static_cast<unsigned char>(value);
        consumed = 1;
      } else {
        unsigned int directCount = remaining;
        if (chunkSize != 0) {
          directCount = remaining - remaining % chunkSize;
        }
        const int bytesRead = ReadFromFileDescriptorWithLock(stream->fileHandle, out, directCount);
        if (bytesRead == 0) {
          stream->flags |= kFlagEndOfFile;
          return (requested - remaining) / elementSize;
        }
        if (bytesRead == -1) {
          stream->flags |= kFlagError;
          return (requested - remaining) / elementSize;
        }
        out += bytesRead;
        consumed = bytesRead;
      }
    } else {
      unsigned int bufferedCount = stream->bytesAvailable;
      if (remaining < bufferedCount) {
        bufferedCount = remaining;
      }
      memcpy(out, stream->cursor, bufferedCount);
      out += bufferedCount;
      stream->cursor += bufferedCount;
      stream->bytesAvailable -= bufferedCount;
      consumed = bufferedCount;
    }

    remaining -= consumed;
  }

  return elementCount;
}

// FUNCTION: IMPERIALISM 0x005e95c0
int ReadNextByteFromBufferedStreamWithLock(BufferedStreamState* stream) {
  EnterStreamCriticalSection(stream);
  const int availableBeforeRead = stream->bytesAvailable;
  --stream->bytesAvailable;
  if (availableBeforeRead - 1 >= 0) {
    const unsigned char value = *stream->cursor;
    ++stream->cursor;
    LeaveStreamCriticalSection(stream);
    return value;
  }

  const int value = RefillBufferedFileStreamAndReadFirstByte(stream);
  LeaveStreamCriticalSection(stream);
  return value;
}

// FUNCTION: IMPERIALISM 0x005edbc0
void EnterStreamCriticalSection(BufferedStreamState* stream) {
  EnterCriticalSection(&stream->criticalSection);
}

// FUNCTION: IMPERIALISM 0x005edc30
void LeaveStreamCriticalSection(BufferedStreamState* stream) {
  LeaveCriticalSection(&stream->criticalSection);
}

// FUNCTION: IMPERIALISM 0x005efd50
int CloseFileDescriptorWithLock(HANDLE fileHandle) {
  return CloseHandle(fileHandle) ? 0 : -1;
}

// FUNCTION: IMPERIALISM 0x005efe50
void WrapperFor_FreeHeapBlockWithAllocatorTracking_At005efe50(BufferedStreamState* stream) {
  if (((stream->flags & 0x83) != 0) && ((stream->flags & kFlagOwnedBuffer) != 0)) {
    delete[] stream->buffer;
    stream->flags &= 0xfffffbf7;
    stream->cursor = 0;
    stream->buffer = 0;
    stream->bytesAvailable = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005eff10
int FlushBufferedStreamPendingWrite(BufferedStreamState* stream) {
  int result = 0;
  if (((stream->flags & 3) == kFlagWrite) && ((stream->flags & 0x108) != 0)) {
    const int byteCount = static_cast<int>(stream->cursor - stream->buffer);
    if (byteCount > 0) {
      DWORD bytesWritten = 0;
      if (!WriteFile(stream->fileHandle, stream->buffer, byteCount, &bytesWritten, 0) ||
          bytesWritten != static_cast<DWORD>(byteCount)) {
        result = -1;
        stream->flags |= kFlagError;
      } else if ((stream->flags & 0x80) != 0) {
        stream->bytesAvailable = 0;
        stream->flags &= 0xfffffffd;
        stream->cursor = stream->buffer;
        return 0;
      }
    }
  }
  stream->bytesAvailable = 0;
  stream->cursor = stream->buffer;
  return result;
}

// FUNCTION: IMPERIALISM 0x005f0050
BufferedStreamState* OpenFileByModeStringAndInitStreamState(const char* path, const char* mode,
                                                            unsigned int streamFlags,
                                                            BufferedStreamState* stream) {
  DWORD access;
  DWORD creationDisposition;
  unsigned int flags;

  if (mode[0] == 'a') {
    access = GENERIC_WRITE;
    creationDisposition = OPEN_ALWAYS;
    flags = kFlagWrite;
  } else if (mode[0] == 'r') {
    access = GENERIC_READ;
    creationDisposition = OPEN_EXISTING;
    flags = kFlagRead;
  } else if (mode[0] == 'w') {
    access = GENERIC_WRITE;
    creationDisposition = CREATE_ALWAYS;
    flags = kFlagWrite;
  } else {
    return 0;
  }

  for (const char* cursor = mode + 1; *cursor != '\0'; ++cursor) {
    switch (*cursor) {
    case '+':
      access = GENERIC_READ | GENERIC_WRITE;
      flags = (flags & 0xfffffffc) | 0x80;
      break;
    case 'b':
      if ((streamFlags & 0xc000) == 0) {
        streamFlags |= kFlagBinary;
      }
      break;
    case 't':
      if ((streamFlags & 0xc000) == 0) {
        streamFlags |= kFlagText;
      }
      break;
    default:
      break;
    }
  }

  HANDLE fileHandle =
      CreateFileA(path, access, FILE_SHARE_READ, 0, creationDisposition, FILE_ATTRIBUTE_NORMAL, 0);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    return 0;
  }

  stream->flags = flags;
  stream->bytesAvailable = 0;
  stream->cursor = 0;
  stream->buffer = 0;
  stream->field1c = 0;
  stream->fileHandle = fileHandle;
  return stream;
}

// FUNCTION: IMPERIALISM 0x005f0220
BufferedStreamState* AcquireAndInitializeBufferedStreamSlot() {
  EnsureBufferedStreamTableLockInitialized();
  EnterCriticalSection(&g_bufferedStreamTableLock);

  BufferedStreamState* stream = 0;
  for (int index = 0; index < kBufferedStreamSlotCount; ++index) {
    if (g_bufferedStreamSlots[index] == 0) {
      g_bufferedStreamSlots[index] = new BufferedStreamState;
      InitializeCriticalSection(&g_bufferedStreamSlots[index]->criticalSection);
      stream = g_bufferedStreamSlots[index];
      EnterCriticalSection(&stream->criticalSection);
      break;
    }

    if ((g_bufferedStreamSlots[index]->flags & 0x83) == 0) {
      stream = g_bufferedStreamSlots[index];
      EnterCriticalSection(&stream->criticalSection);
      if ((stream->flags & 0x83) != 0) {
        LeaveCriticalSection(&stream->criticalSection);
        stream = 0;
      } else {
        break;
      }
    }
  }

  if (stream != 0) {
    stream->bytesAvailable = 0;
    stream->flags = 0;
    stream->buffer = 0;
    stream->cursor = 0;
    stream->field1c = 0;
    stream->fileHandle = INVALID_HANDLE_VALUE;
    stream->bufferSize = kDefaultBufferSize;
  }

  LeaveCriticalSection(&g_bufferedStreamTableLock);
  return stream;
}

// FUNCTION: IMPERIALISM 0x005f1490
int RefillBufferedFileStreamAndReadFirstByte(BufferedStreamState* stream) {
  if ((stream->flags & 0x83) == 0) {
    return -1;
  }

  if ((stream->flags & kFlagWrite) != 0) {
    stream->flags |= kFlagError;
    return -1;
  }

  stream->flags |= kFlagRead;
  if ((stream->flags & 0x10c) == 0) {
    stream->buffer = new unsigned char[kDefaultBufferSize];
    stream->bufferSize = kDefaultBufferSize;
    stream->flags |= kFlagOwnedBuffer;
  } else {
    stream->cursor = stream->buffer;
  }

  const int bytesRead =
      ReadFromFileDescriptorWithLock(stream->fileHandle, stream->buffer, stream->bufferSize);
  stream->bytesAvailable = bytesRead;
  if (bytesRead != 0 && bytesRead != -1) {
    stream->bytesAvailable = bytesRead - 1;
    const unsigned char value = stream->buffer[0];
    stream->cursor = stream->buffer + 1;
    return value;
  }

  stream->bytesAvailable = 0;
  stream->flags |= kFlagEndOfFile;
  if (bytesRead == -1) {
    stream->flags |= kFlagError;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x005f1580
int ReadFromFileDescriptorWithLock(HANDLE fileHandle, void* buffer, unsigned int byteCount) {
  DWORD bytesRead = 0;
  if (!ReadFile(fileHandle, buffer, byteCount, &bytesRead, 0)) {
    return -1;
  }
  return static_cast<int>(bytesRead);
}
