#pragma once

class RuntimeTestCase;

RuntimeTestCase* BootManagersTest();
RuntimeTestCase* RandomGameJourneyTest();
RuntimeTestCase* EasyRandomGameTest();
RuntimeTestCase* IntroductoryRandomGameTest();
RuntimeTestCase* EndTurnTest();
RuntimeTestCase* MultiTurnAdvanceTest();
RuntimeTestCase* CityScreenTest();
RuntimeTestCase* TransportScreenTest();
RuntimeTestCase* CivilianRecruitmentTest();
RuntimeTestCase* DiplomacyScreenTest();
RuntimeTestCase* TradeScreenTest();
RuntimeTestCase* MapZoomToggleTest();
RuntimeTestCase* ArmyMenuTest();
RuntimeTestCase* LoadSavedGameTest();
RuntimeTestCase* SerializationRoundtripTest();
RuntimeTestCase* SaveStreamCheckpointTest();
RuntimeTestCase* SaveLoadRoundtripTest();
RuntimeTestCase* RandomControlExplorerTest();
RuntimeTestCase* UnknownRuntimeTest();
