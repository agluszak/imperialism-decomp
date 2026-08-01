#pragma once

#include "decomp_types.h"

// Newspaper event kinds share an int-sized discriminator in TNewsMgr's 0x10-byte
// heterogeneous record queue. Names below are limited to meanings proven by the
// producing gameplay paths; gaps are valid but currently unnamed retail kinds.
enum InterNationEventKind {
  kInterNationEventWarDeclaredBySubject = 0x00,
  kInterNationEventWarDeclaredAgainstSubject = 0x01,
  kInterNationEventPeaceTreatyAccepted = 0x02,
  kInterNationEventJoinEmpireAccepted = 0x03,
  kInterNationEventAllianceAccepted = 0x04,
  kInterNationEventNonAggressionPactAccepted = 0x05,
  kInterNationEventPeaceTreatyRejected = 0x07,
  kInterNationEventJoinEmpireRejected = 0x09,
  kInterNationEventAllianceRejected = 0x0B,
  kInterNationEventNonAggressionPactRejected = 0x0D,
  kInterNationEventShortage = 0x0F,
  kInterNationEventMiscellaneous = 0x11,
  kInterNationEventTradeConsulateEstablished = 0x12,
  kInterNationEventEmbassyEstablished = 0x14,
  kInterNationEventMinorEmpireAffiliationChanged = 0x16,
  kInterNationEventMinorTerritoryRelationshipAffected = 0x17,
  kInterNationEventPeaceRelationshipPropagated = 0x18,
  kInterNationEventWarWithIndependentMinor = 0x19,
  kInterNationEventAllianceRelationshipEstablished = 0x1A,
  kInterNationEventNationJoinedEmpire = 0x1B,
  kInterNationEventNationJoinedWar = 0x1C,
  kInterNationEventNationTransferred = 0x1D
};

// Mac CodeWarrior names this 0x24-byte payload NewsEvent. Windows event 0x13
// transports all nine dwords verbatim, while the known producer initializes only
// the first four. Preserve the five untouched dwords rather than inventing fields.
struct NewsEvent {
  int marker0;
  int subjectNationMask4;
  int marker8;
  int targetNationMask0C;
  int reserved10[5];
};

// The shared TNewsMgr queue stores one three-dword payload. eventKind determines whether
// the second dword is a nation mask or story code and whether the third dword is used.
struct InterNationNewsPayload {
  int subjectNationOrAll;
  int nationMaskOrStoryCode;
  int relatedNation;
};

struct InterNationNewsRecord {
  InterNationEventKind eventKind;
  InterNationNewsPayload payload;
};

ASSERT_SIZE(NewsEvent, 0x24);
ASSERT_SIZE(InterNationNewsRecord, 0x10);
