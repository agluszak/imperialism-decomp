#pragma once

// Diplomacy turn-event nation filter. Implementation lives in
// TDiplomacyMgr.cpp (primary consumer of eligibility checks).
char IsNationSlotEligibleForEventProcessing(short nationSlot);
