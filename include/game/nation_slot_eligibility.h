#pragma once

// Diplomacy turn-event nation filter. Implementation lives in
// TDiplomacyTurnStateManager.cpp (primary consumer of eligibility checks).
char IsNationSlotEligibleForEventProcessing(short nationSlot);
