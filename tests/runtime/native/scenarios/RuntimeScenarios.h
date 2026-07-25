#pragma once

class RuntimeTestCase;

RuntimeTestCase* BootManagersTest();
RuntimeTestCase* RandomGameJourneyTest();
RuntimeTestCase* EasyRandomGameTest();
RuntimeTestCase* EndTurnTest();
RuntimeTestCase* CityScreenTest();
RuntimeTestCase* DiplomacyScreenTest();
RuntimeTestCase* TradeScreenTest();
RuntimeTestCase* MapZoomToggleTest();
RuntimeTestCase* LoadSavedGameTest();
RuntimeTestCase* TurnEventQueueBoundsTest();
RuntimeTestCase* SerializationRoundtripTest();
RuntimeTestCase* SaveStreamCheckpointTest();
RuntimeTestCase* SaveLoadRoundtripTest();
RuntimeTestCase* UnknownRuntimeTest();
