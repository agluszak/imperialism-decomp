#pragma once
// Unresolved address-named global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp; promote a declaration to its owner header only
// after its domain and contract are recovered. The mapped flavor-text literal block was
// promoted to game/globals/mapped_flavor_literals.h.
#include "game/globals/global_types.h"

extern "C" {

// Assert source-path strings not yet owned by a narrower subsystem surface.
extern const char s_SourcePathUViewMgr_0069B6BC[];
extern const char s_SourcePathUTradeViews_0069AA94[];

// TSimMgr's opaque debug tag literal.
extern const char s_Chunk_00698C0C[];
} // extern "C"
