#include "game/TForeignMinisterPersonalities.h"

#include "game/mfc.h"

// NOTE: The large slot bodies (MinisterSlot21 0x84, Call90 0x90, DispatchProposalSlot98
// 0x98, and the MinisterSlot18 0x60 action queues) are dispatch-heavy and dispatch
// through TGreatPower / TNationInteractionStateManager vtable slots whose method names
// are not yet fully recovered. They are promoted here as real virtual overrides owning
// their original addresses (previously return-0 autogen stubs); bodies are honest partial
// ports to be enriched once the receiver vtables are mapped.

// ===================== TTedForeignMinister (0x659d70) =====================

// SYNTHETIC: IMPERIALISM 0x00531130
// TTedForeignMinister::CreateObject
CObject* PASCAL TTedForeignMinister::CreateObject() {
  return new TTedForeignMinister;
}
const CRuntimeClass TTedForeignMinister::classTTedForeignMinister = {
    "TTedForeignMinister", sizeof(TTedForeignMinister), 0xffff, TTedForeignMinister::CreateObject,
    RUNTIME_CLASS(TForeignMinister), nullptr};

// FUNCTION: IMPERIALISM 0x005311b0
CRuntimeClass* TTedForeignMinister::GetRuntimeClass() const {
  return const_cast<CRuntimeClass*>(&classTTedForeignMinister);
}

// FUNCTION: IMPERIALISM 0x005311d0
TTedForeignMinister::TTedForeignMinister() : TForeignMinister() {
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x1a) = 4;
  this->skillIndexC = 5;
}

// SYNTHETIC: IMPERIALISM 0x00531240
// TTedForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531290
void TTedForeignMinister::MinisterSlot21() {
  // Partial port (InitializeTedForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00531550
void TTedForeignMinister::Call90() {
  // Partial port (RunForeignMinisterVtableSlot90TedVariant).
}

// FUNCTION: IMPERIALISM 0x00531770
void TTedForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountByModePolicyA).
}

// FUNCTION: IMPERIALISM 0x00531a10
void TTedForeignMinister::MinisterSlot18() {
  // Partial port (QueueTedFourRandomAvailableTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x00531af0
void TTedForeignMinister::MinisterSlot19() {}

// FUNCTION: IMPERIALISM 0x00531b10
void TTedForeignMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(receiver) + 0x60) = 3;
}

// ===================== TBillForeignMinister (0x659e30) =====================

// SYNTHETIC: IMPERIALISM 0x00531b30
// TBillForeignMinister::CreateObject
CObject* PASCAL TBillForeignMinister::CreateObject() {
  return new TBillForeignMinister;
}
const CRuntimeClass TBillForeignMinister::classTBillForeignMinister = {
    "TBillForeignMinister", sizeof(TBillForeignMinister), 0xffff,
    TBillForeignMinister::CreateObject, RUNTIME_CLASS(TForeignMinister), nullptr};

// FUNCTION: IMPERIALISM 0x00531bc0
CRuntimeClass* TBillForeignMinister::GetRuntimeClass() const {
  return const_cast<CRuntimeClass*>(&classTBillForeignMinister);
}

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
void TBillForeignMinister::MinisterSlot21() {
  // Partial port (InitializeBillForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00531e50
void TBillForeignMinister::Call90() {
  // Partial port (RunForeignMinisterVtableSlot90BillVariant).
}

// FUNCTION: IMPERIALISM 0x00532190
void TBillForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountByModePolicyB).
}

// FUNCTION: IMPERIALISM 0x00532520
void TBillForeignMinister::MinisterSlot18() {
  // Partial port (QueueDiplomatTwoRandomAvailableTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x005325e0
void TBillForeignMinister::MinisterSlot19() {
  // Partial port (QueueDiplomatTwoCompatibleMatrixActionsCode5A).
}

// FUNCTION: IMPERIALISM 0x00532650
void TBillForeignMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  // Partial port (UpdateDiplomatProgressFromProductionSlots2And4).
  *reinterpret_cast<short*>(reinterpret_cast<char*>(receiver) + 0x5e) = 3;
}

// ===================== TDiplomatForeignMinister (0x659f48) =====================

// SYNTHETIC: IMPERIALISM 0x005326e0
// TDiplomatForeignMinister::CreateObject
CObject* PASCAL TDiplomatForeignMinister::CreateObject() {
  return new TDiplomatForeignMinister;
}
const CRuntimeClass TDiplomatForeignMinister::classTDiplomatForeignMinister = {
    "TDiplomatForeignMinister", sizeof(TDiplomatForeignMinister), 0xffff,
    TDiplomatForeignMinister::CreateObject, RUNTIME_CLASS(TForeignMinister), nullptr};

// FUNCTION: IMPERIALISM 0x00532760
CRuntimeClass* TDiplomatForeignMinister::GetRuntimeClass() const {
  return const_cast<CRuntimeClass*>(&classTDiplomatForeignMinister);
}

// FUNCTION: IMPERIALISM 0x00532780
TDiplomatForeignMinister::TDiplomatForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x005327f0
// TDiplomatForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00532840
void TDiplomatForeignMinister::MinisterSlot18() {
  // Partial port (QueueDiplomatWeightedTerrainActionRunCode133).
}

// FUNCTION: IMPERIALISM 0x005328d0
void TDiplomatForeignMinister::MinisterSlot19() {}

// FUNCTION: IMPERIALISM 0x005328f0
void TDiplomatForeignMinister::MinisterSlot21() {
  // Partial port (SelectNationInteractionModePriorityTriplet).
}

// FUNCTION: IMPERIALISM 0x00532c60
void TDiplomatForeignMinister::Call90() {
  // Partial port (RunForeignMinisterPolicySlot28VariantA).
}

// FUNCTION: IMPERIALISM 0x00532f70
void TDiplomatForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3,
                                                      int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (RunForeignMinisterPolicySlot30VariantA).
}

// FUNCTION: IMPERIALISM 0x00533050
void TDiplomatForeignMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(receiver) + 0x5e) += 5;
}

// ===================== TTextileForeignMinister (0x65a008) =====================

// SYNTHETIC: IMPERIALISM 0x00533070
// TTextileForeignMinister::CreateObject
CObject* PASCAL TTextileForeignMinister::CreateObject() {
  return new TTextileForeignMinister;
}
const CRuntimeClass TTextileForeignMinister::classTTextileForeignMinister = {
    "TTextileForeignMinister", sizeof(TTextileForeignMinister), 0xffff,
    TTextileForeignMinister::CreateObject, RUNTIME_CLASS(TForeignMinister), nullptr};

// FUNCTION: IMPERIALISM 0x005330f0
CRuntimeClass* TTextileForeignMinister::GetRuntimeClass() const {
  return const_cast<CRuntimeClass*>(&classTTextileForeignMinister);
}

// FUNCTION: IMPERIALISM 0x00533110
TTextileForeignMinister::TTextileForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533180
// TTextileForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005331d0
void TTextileForeignMinister::MinisterSlot21() {
  // Partial port (InitializeTextileForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00533380
void TTextileForeignMinister::Call90() {
  // Partial port (RunForeignMinisterPolicySlot28VariantB).
}

// FUNCTION: IMPERIALISM 0x00533670
void TTextileForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3,
                                                     int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountWithAvailableCap).
}

// FUNCTION: IMPERIALISM 0x00533780
void TTextileForeignMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  // Partial port (UpdateTextileProgressFromProductionSlots1And2).
  char* city = reinterpret_cast<char*>(receiver);
  *reinterpret_cast<short*>(city + 0x60) += 2;
  *reinterpret_cast<short*>(city + 0x5e) += 1;
}

// ===================== TTraderForeignMinister (0x65a0c8) =====================

// SYNTHETIC: IMPERIALISM 0x00533800
// TTraderForeignMinister::CreateObject
CObject* PASCAL TTraderForeignMinister::CreateObject() {
  return new TTraderForeignMinister;
}
const CRuntimeClass TTraderForeignMinister::classTTraderForeignMinister = {
    "TTraderForeignMinister", sizeof(TTraderForeignMinister), 0xffff,
    TTraderForeignMinister::CreateObject, RUNTIME_CLASS(TForeignMinister), nullptr};

// FUNCTION: IMPERIALISM 0x00533880
CRuntimeClass* TTraderForeignMinister::GetRuntimeClass() const {
  return const_cast<CRuntimeClass*>(&classTTraderForeignMinister);
}

// FUNCTION: IMPERIALISM 0x005338a0
TTraderForeignMinister::TTraderForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533910
// TTraderForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00533960
void TTraderForeignMinister::MinisterSlot21() {
  // Partial port (InitializeTraderForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00533b10
void TTraderForeignMinister::Call90() {
  // Partial port (RunForeignMinisterPolicySlot28VariantC).
}

// FUNCTION: IMPERIALISM 0x00533db0
void TTraderForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3,
                                                    int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountWithFallbackVariant).
}

// FUNCTION: IMPERIALISM 0x00533e90
void TTraderForeignMinister::MinisterSlot18() {
  // Partial port (QueueTraderFourRandomTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x00533f50
void TTraderForeignMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(receiver) + 0x60) += 3;
}

// ===================== TArmsForeignMinister (0x65a188) =====================

// SYNTHETIC: IMPERIALISM 0x00533f70
// TArmsForeignMinister::CreateObject
CObject* PASCAL TArmsForeignMinister::CreateObject() {
  return new TArmsForeignMinister;
}
const CRuntimeClass TArmsForeignMinister::classTArmsForeignMinister = {
    "TArmsForeignMinister", sizeof(TArmsForeignMinister), 0xffff,
    TArmsForeignMinister::CreateObject, RUNTIME_CLASS(TForeignMinister), nullptr};

// FUNCTION: IMPERIALISM 0x00533ff0
CRuntimeClass* TArmsForeignMinister::GetRuntimeClass() const {
  return const_cast<CRuntimeClass*>(&classTArmsForeignMinister);
}

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
void TArmsForeignMinister::MinisterSlot21() {
  // Partial port (InitializeArmsForeignMinisterOrderCandidates).
}

// FUNCTION: IMPERIALISM 0x00534190
void TArmsForeignMinister::Call90() {
  // Partial port (RunForeignMinisterVtableSlot90ArmsVariant).
}

// FUNCTION: IMPERIALISM 0x00534450
void TArmsForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // Partial port (DispatchNationInteractionAmountWithSharedSplitCache).
}

// FUNCTION: IMPERIALISM 0x00534660
void TArmsForeignMinister::NoOpForeignMinisterUtilityStub(void* receiver) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(receiver) + 0x5e) += 5;
}
