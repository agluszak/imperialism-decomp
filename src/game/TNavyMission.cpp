#include "game/TNavyMission.h"

#include "game/TDiplomacyMgr.h"
#include "game/diplomacy_globals.h"
#include "game/TShip.h"

extern "C" {
extern float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern unsigned short g_Populate_Beachhead_Mission_LookupTable_00697958[];
}


undefined4 GetNavyOrderNormalizationBaseByNationType(void);
undefined4 ComputeNavyOrderPriorityContributionPercentByCategory(void);

namespace {

struct NavyPrimaryOrderNode {
  char pad00[8];
  int nodeContext08;
  char pad0c[8];
  short sourceNation14;
  char pad16[6];
  short weight1c;
  char pad1e[6];
  void* next24;
};

float NormalizeFourComponentNavyVector(const float* vector, float sum) {
  if (sum == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  const unsigned short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  float accum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    float diff = vector[componentIndex] / sum -
                 static_cast<float>(static_cast<short>(lookupTable[componentIndex])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    accum += diff;
  }
  return sum * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                accum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}

void AccumulateNavyOrderVectorFromNode(NavyPrimaryOrderNode* orderNode, float* vector) {
  short normalizationBase =
      reinterpret_cast<short(__cdecl*)(void)>(GetNavyOrderNormalizationBaseByNationType)();
  if (normalizationBase == 0) {
    return;
  }
  float scale = static_cast<float>(orderNode->weight1c / normalizationBase);
  int category = static_cast<int>(orderNode->weight1c % normalizationBase);
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    short contribution = reinterpret_cast<short(__fastcall*)(void*, int)>(
        ComputeNavyOrderPriorityContributionPercentByCategory)(orderNode, category);
    if (componentIndex < 3) {
      vector[componentIndex] += static_cast<float>(contribution) * scale;
    } else {
      vector[componentIndex] += static_cast<float>(contribution);
    }
    category = static_cast<int>(contribution);
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x005389f0
float TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                               int nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (NavyPrimaryOrderNode* orderNode =
           reinterpret_cast<NavyPrimaryOrderNode*>(GetNavyPrimaryOrderListHead());
       orderNode != 0; orderNode = reinterpret_cast<NavyPrimaryOrderNode*>(orderNode->next24)) {
    if (orderNode->nodeContext08 == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(static_cast<short>(sourceNation),
                                                                orderNode->sourceNation14) != 0) {
      AccumulateNavyOrderVectorFromNode(orderNode, vector);
    }
  }
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += vector[componentIndex];
  }
  return NormalizeFourComponentNavyVector(vector, sum);
}

// FUNCTION: IMPERIALISM 0x00538bf0
float TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                                int nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (NavyPrimaryOrderNode* orderNode =
           reinterpret_cast<NavyPrimaryOrderNode*>(GetNavyPrimaryOrderListHead());
       orderNode != 0; orderNode = reinterpret_cast<NavyPrimaryOrderNode*>(orderNode->next24)) {
    if (orderNode->nodeContext08 == nodeContext &&
        static_cast<short>(sourceNation) == orderNode->sourceNation14) {
      AccumulateNavyOrderVectorFromNode(orderNode, vector);
    }
  }
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += vector[componentIndex];
  }
  return NormalizeFourComponentNavyVector(vector, sum);
}
