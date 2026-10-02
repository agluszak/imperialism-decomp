#pragma once

#include "game/city_ui/TLongintList.h"

#include "game/core/stream_byteswap.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/military/TUnit.h"

void WriteTrackedListToStream(TStream* stream, TSortedList* list);
void WriteIntListToStream(TStream* stream, TLongintList* list);
