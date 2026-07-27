#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/prelude.h"

// Initial city recruitment profiles for order slots 0x22..0x2a. 0x695c50.
extern short g_aInitialCityRecruitmentOrderProfiles[9][7];

extern "C" {
extern char g_Sanitize_City_Counter_Value_006A24D4;

} // extern "C"
