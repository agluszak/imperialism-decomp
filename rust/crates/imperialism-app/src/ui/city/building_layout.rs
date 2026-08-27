use crate::ui::generated;
use bevy::prelude::*;
use imperialism_core::CityFacilitySlot;

pub(in crate::ui::city) fn spawn_city_dialog(
    commands: &mut Commands,
    slot: CityFacilitySlot,
) -> Entity {
    match slot {
        CityFacilitySlot::TextileMill => commands.spawn_scene(generated::citydlog_9200()).id(),
        CityFacilitySlot::ClothingFactory => commands.spawn_scene(generated::citydlog_9201()).id(),
        CityFacilitySlot::SteelMill => commands.spawn_scene(generated::citydlog_9202()).id(),
        CityFacilitySlot::Metalworks => commands.spawn_scene(generated::citydlog_9203()).id(),
        CityFacilitySlot::LumberMill => commands.spawn_scene(generated::citydlog_9204()).id(),
        CityFacilitySlot::FurnitureFactory => commands.spawn_scene(generated::citydlog_9205()).id(),
        CityFacilitySlot::OilRefinery => commands.spawn_scene(generated::citydlog_9206()).id(),
        CityFacilitySlot::Shipyard => commands.spawn_scene(generated::shipyard_9207()).id(),
        CityFacilitySlot::Armory => commands.spawn_scene(generated::armory_9208()).id(),
        CityFacilitySlot::TradeSchool => commands.spawn_scene(generated::citydlog_9209()).id(),
        CityFacilitySlot::University => commands.spawn_scene(generated::univ_9210()).id(),
        CityFacilitySlot::PowerPlant => commands.spawn_scene(generated::citydlog_9211()).id(),
        CityFacilitySlot::FoodProcessing => commands.spawn_scene(generated::citydlog_9212()).id(),
        CityFacilitySlot::Warehouse => commands.spawn_scene(generated::citydlog_9213()).id(),
        CityFacilitySlot::Transport => commands.spawn_scene(generated::citydlog_9214()).id(),
        CityFacilitySlot::RegionalPopulation => {
            commands.spawn_scene(generated::citydlog_9215()).id()
        }
    }
}
