#include "game/TForeignMinisterPersonalities.h"

#include "game/TCity.h"
#include "game/mfc.h"

// NOTE: The large slot bodies (SetBuyPriorities 0x84, SetTradeBids 0x90, ReplyToTradeOffer
// 0x98, and the DoFirstTurnDiplomacy 0x60 action queues) are dispatch-heavy and dispatch
// through TGreatPower / TNationInteractionStateManager vtable slots whose method names
// are not yet fully recovered. They are promoted here as real virtual overrides owning
// their original addresses (previously return-0 autogen stubs); bodies are honest partial
// ports to be enriched once the receiver vtables are mapped.

// ===================== TTedForeignMinister (0x659d70) =====================

// SYNTHETIC: IMPERIALISM 0x00531130
// TTedForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x005311b0
// TTedForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTedForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005311d0
TTedForeignMinister::TTedForeignMinister() : TForeignMinister() {
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x1a) = 4;
  this->skillIndexC = 5;
}

// SYNTHETIC: IMPERIALISM 0x00531240
// TTedForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531290
void TTedForeignMinister::SetBuyPriorities() {
  // Partial port (InitializeTedForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00531550
void TTedForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterVtableSlot90TedVariant).
}

// FUNCTION: IMPERIALISM 0x00531770
void TTedForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                            short targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountByModePolicyA).
}

// FUNCTION: IMPERIALISM 0x00531a10
void TTedForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueTedFourRandomAvailableTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x00531af0
void TTedForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x00531b10
void TTedForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] = 3;
}

// ===================== TBillForeignMinister (0x659e30) =====================

// SYNTHETIC: IMPERIALISM 0x00531b30
// TBillForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00531bc0
// TBillForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TBillForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00531be0
TBillForeignMinister::TBillForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00531c50
// TBillForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531ca0
void TBillForeignMinister::ReadFrom(TStream* stream) {
  this->SerializeTMinisterBaseOrderArrayHeader(stream);
  // Partial port: original also reads the order-flag byte at +0x80.
}

// FUNCTION: IMPERIALISM 0x00531ce0
void TBillForeignMinister::WriteTo(TStream* stream) {
  this->SerializeTMinisterBaseOrderArrayHeader(stream);
  // Partial port: original also writes the order-flag byte at +0x80.
}

// FUNCTION: IMPERIALISM 0x00531d20
void TBillForeignMinister::SetBuyPriorities() {
  // Partial port (InitializeBillForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00531e50
void TBillForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterVtableSlot90BillVariant).
}

// FUNCTION: IMPERIALISM 0x00532190
void TBillForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                             short targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountByModePolicyB).
}

// FUNCTION: IMPERIALISM 0x00532520
void TBillForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueDiplomatTwoRandomAvailableTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x005325e0
void TBillForeignMinister::DoSecondTurnDiplomacy() {
  // Partial port (QueueDiplomatTwoCompatibleMatrixActionsCode5A).
}

// FUNCTION: IMPERIALISM 0x00532650
void TBillForeignMinister::MakeNewCity(TCity* city) {
  // Partial port (UpdateDiplomatProgressFromProductionSlots2And4).
  city->orderCountByType5c[1] = 3;
}

// ===================== TDiplomatForeignMinister (0x659f48) =====================

// SYNTHETIC: IMPERIALISM 0x005326e0
// TDiplomatForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00532760
// TDiplomatForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TDiplomatForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00532780
TDiplomatForeignMinister::TDiplomatForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x005327f0
// TDiplomatForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00532840
void TDiplomatForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueDiplomatWeightedTerrainActionRunCode133).
}

// FUNCTION: IMPERIALISM 0x005328d0
void TDiplomatForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x005328f0
void TDiplomatForeignMinister::SetBuyPriorities() {
  // Partial port (SelectNationInteractionModePriorityTriplet).
}

// FUNCTION: IMPERIALISM 0x00532c60
void TDiplomatForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterPolicySlot28VariantA).
}

// FUNCTION: IMPERIALISM 0x00532f70
void TDiplomatForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                                 short targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (RunForeignMinisterPolicySlot30VariantA).
}

// FUNCTION: IMPERIALISM 0x00533050
void TDiplomatForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] += 5;
}

// ===================== TTextileForeignMinister (0x65a008) =====================

// SYNTHETIC: IMPERIALISM 0x00533070
// TTextileForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x005330f0
// TTextileForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTextileForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00533110
TTextileForeignMinister::TTextileForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533180
// TTextileForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005331d0
void TTextileForeignMinister::SetBuyPriorities() {
  // Partial port (InitializeTextileForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00533380
void TTextileForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterPolicySlot28VariantB).
}

// FUNCTION: IMPERIALISM 0x00533670
void TTextileForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                                short targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountWithAvailableCap).
}

// FUNCTION: IMPERIALISM 0x00533780
void TTextileForeignMinister::MakeNewCity(TCity* city) {
  // Partial port (UpdateTextileProgressFromProductionSlots1And2).
  city->orderCountByType5c[2] += 2;
  city->orderCountByType5c[1] += 1;
}

// ===================== TTraderForeignMinister (0x65a0c8) =====================

// SYNTHETIC: IMPERIALISM 0x00533800
// TTraderForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00533880
// TTraderForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTraderForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005338a0
TTraderForeignMinister::TTraderForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533910
// TTraderForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00533960
void TTraderForeignMinister::SetBuyPriorities() {
  // Partial port (InitializeTraderForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00533b10
void TTraderForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterPolicySlot28VariantC).
}

// FUNCTION: IMPERIALISM 0x00533db0
void TTraderForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                               short targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountWithFallbackVariant).
}

// FUNCTION: IMPERIALISM 0x00533e90
void TTraderForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueTraderFourRandomTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x00533f50
void TTraderForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] += 3;
}

// ===================== TArmsForeignMinister (0x65a188) =====================

// SYNTHETIC: IMPERIALISM 0x00533f70
// TArmsForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00533ff0
// TArmsForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TArmsForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00534010
TArmsForeignMinister::TArmsForeignMinister() : TForeignMinister() {
  char* raw = reinterpret_cast<char*>(this);
  raw[0x48] = 1;
  *reinterpret_cast<short*>(raw + 0x1a) = 4;
  *reinterpret_cast<short*>(raw + 0x1c) = 0;
}

// SYNTHETIC: IMPERIALISM 0x00534080
// TArmsForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005340d0
void TArmsForeignMinister::SetBuyPriorities() {
  // Partial port (InitializeArmsForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00534190
void TArmsForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterVtableSlot90ArmsVariant).
}

// FUNCTION: IMPERIALISM 0x00534450
void TArmsForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                             short targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountWithSharedSplitCache).
}

// FUNCTION: IMPERIALISM 0x00534660
void TArmsForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] += 5;
}
