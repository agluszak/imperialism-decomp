# Trade Bitmap Truth Table

Grounded sources:
- GOB resource listings (`pictenu.gob`, `pictpaid.gob`, `pictuniv.gob`)
- Literal `+0x1c8` picture assignments in `InitializeTradeScreenBitmapControls` (`0x004601b0`)
- Pressed-state derivation path (`SetPressedStateAdjustPictureBitmapByOne`)

| id | hex | resource_present | resource_gobs | literal_in_0x004601b0 | derived_via_pressed_state | classification | notes |
|---:|:---:|:---:|:---|:---:|:---:|:---|:---|
| 2101 | `0x0835` | 1 | `pictuniv.gob` | 0 | 0 | `resource_present_not_literal_in_trade_init` | trade_background_pre_oil | gobs=pictuniv.gob |
| 2102 | `0x0836` | 1 | `pictpaid.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_background_post_oil | gobs=pictpaid.gob |
| 2103 | `0x0837` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2104 | `0x0838` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2105 | `0x0839` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2106 | `0x083a` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2107 | `0x083b` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2108 | `0x083c` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2109 | `0x083d` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2110 | `0x083e` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2111 | `0x083f` | 1 | `pictenu.gob` | 0 | 0 | `resource_present_not_literal_in_trade_init` | trade_bid_state_a | gobs=pictenu.gob |
| 2112 | `0x0840` | 1 | `pictuniv.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_bid_secondary_state_a | gobs=pictuniv.gob |
| 2113 | `0x0841` | 1 | `pictenu.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_offer_state_a | gobs=pictenu.gob |
| 2114 | `0x0842` | 1 | `pictuniv.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_offer_secondary_state_a | gobs=pictuniv.gob |
| 2115 | `0x0843` | 0 | `` | 0 | 0 | `unresolved_candidate_no_code_hits` | global_code_hits=0 |
| 2116 | `0x0844` | 0 | `` | 0 | 0 | `struct_offset_constant_not_bitmap_id` | global_code_hits=16 | sample_sites=004b1e9a:CreateTLaborPoolInstance; 004d8a5d:ConstructNationStateBase_Vtbl653938; 004d94fe:InitializeGreatPowerMinisterRosterAndScenarioState; 004d9f5c:HandleCityDialogHintClusterUpdate; 004dd1cb:ResetDiplomacyNeedScoresAndClearAidAllocationMatrix |
| 2117 | `0x0845` | 0 | `` | 0 | 0 | `unresolved_candidate_no_code_hits` | global_code_hits=0 |
| 2118 | `0x0846` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2119 | `0x0847` | 0 | `` | 0 | 0 | `absent_from_resources_and_trade_literals` |  |
| 2120 | `0x0848` | 1 | `pictuniv.gob` | 1 | 1 | `literal_trade_bitmap_id` | trade_green_control_base | gobs=pictuniv.gob |
| 2121 | `0x0849` | 1 | `pictuniv.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_decrease_arrow_base | gobs=pictuniv.gob |
| 2122 | `0x084a` | 1 | `pictuniv.gob` | 0 | 1 | `derived_runtime_state_id` | trade_decrease_arrow_pressed_derived | gobs=pictuniv.gob |
| 2123 | `0x084b` | 1 | `pictuniv.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_increase_arrow_base | gobs=pictuniv.gob |
| 2124 | `0x084c` | 1 | `pictuniv.gob` | 0 | 1 | `derived_runtime_state_id` | trade_increase_arrow_pressed_derived | gobs=pictuniv.gob |
| 2125 | `0x084d` | 1 | `pictenu.gob` | 0 | 0 | `resource_present_not_literal_in_trade_init` | trade_bid_state_b | gobs=pictenu.gob |
| 2126 | `0x084e` | 1 | `pictuniv.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_bid_secondary_state_b | gobs=pictuniv.gob |
| 2127 | `0x084f` | 1 | `pictenu.gob` | 0 | 0 | `resource_present_not_literal_in_trade_init` | trade_offer_state_b | gobs=pictenu.gob |
| 2128 | `0x0850` | 1 | `pictuniv.gob` | 1 | 0 | `literal_trade_bitmap_id` | trade_offer_secondary_state_b | gobs=pictuniv.gob |
