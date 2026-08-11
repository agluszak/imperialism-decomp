use super::*;

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    catalog.require_unique_bindings(
        &city_view_id(),
        &[
            fourcc!("main"),
            fourcc!("labP"),
            fourcc!("untr"),
            fourcc!("trai"),
            fourcc!("prof"),
            fourcc!("powe"),
            fourcc!("grai"),
            fourcc!("prod"),
            fourcc!("meat"),
            fourcc!("hard"),
            fourcc!("clot"),
            fourcc!("furn"),
            fourcc!("trea"),
        ],
    )?;
    let city = catalog
        .view(&city_view_id())
        .expect("city view was validated above");
    if city.city_buildings.len() != CityFacilitySlot::COUNT {
        return Err(format!(
            "Citymain.rsrc:2011 has {} dynamic buildings; expected {}",
            city.city_buildings.len(),
            CityFacilitySlot::COUNT
        ));
    }
    let dialog = |slot| {
        city.city_buildings
            .iter()
            .find(|building| building.slot == slot)
            .map(|building| &building.dialog)
            .ok_or_else(|| format!("Citymain.rsrc:2011 is missing {slot:?}"))
    };
    for slot in [
        CityFacilitySlot::TextileMill,
        CityFacilitySlot::ClothingFactory,
        CityFacilitySlot::SteelMill,
        CityFacilitySlot::Metalworks,
        CityFacilitySlot::LumberMill,
        CityFacilitySlot::FurnitureFactory,
        CityFacilitySlot::OilRefinery,
    ] {
        let page = industry_page(slot).expect("ordinary industry has a page");
        let view_id = dialog(slot)?;
        catalog.require_unique_bindings(
            view_id,
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("labV"),
                fourcc!("name"),
                fourcc!("capT"),
                fourcc!("expa"),
                fourcc!("flag"),
            ],
        )?;
        for binding in page.orders {
            for tag in [
                fourcc!("left"),
                fourcc!("rght"),
                fourcc!("move"),
                fourcc!("bar "),
            ] {
                catalog.require_control_under(view_id, tag, &[binding.tag])?;
            }
        }
        for &(_, tag, _) in page.stocks {
            catalog.require_unique_bindings(view_id, &[tag])?;
        }
    }
    for (slot, bindings, unique_tags) in [
        (
            CityFacilitySlot::TradeSchool,
            TRAINING_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("cos1"),
                fourcc!("cos2"),
                fourcc!("pap1"),
                fourcc!("pap2"),
                fourcc!("mon1"),
                fourcc!("mon2"),
                fourcc!("untV"),
                fourcc!("traV"),
            ][..],
        ),
        (
            CityFacilitySlot::FoodProcessing,
            FOOD_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("labV"),
                fourcc!("grai"),
                fourcc!("prod"),
                fourcc!("fish"),
            ],
        ),
        (
            CityFacilitySlot::PowerPlant,
            POWER_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("fuel"),
            ],
        ),
        (
            CityFacilitySlot::Transport,
            TRANSPORT_CAPACITY_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("labV"),
                fourcc!("lumb"),
                fourcc!("stee"),
            ],
        ),
        (
            CityFacilitySlot::RegionalPopulation,
            POPULATION_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("food"),
                fourcc!("clot"),
                fourcc!("furn"),
                fourcc!("capT"),
                fourcc!("prov"),
            ],
        ),
    ] {
        let view_id = dialog(slot)?;
        catalog.require_unique_bindings(view_id, unique_tags)?;
        for binding in bindings {
            for tag in [
                fourcc!("left"),
                fourcc!("rght"),
                fourcc!("move"),
                fourcc!("bar "),
            ] {
                catalog.require_control_under(view_id, tag, &[binding.tag])?;
            }
        }
    }
    let warehouse = dialog(CityFacilitySlot::Warehouse)?;
    catalog.require_unique_bindings(
        warehouse,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("name"),
            fourcc!("labo"),
            fourcc!("powe"),
        ],
    )?;
    for &(_, tag) in &WAREHOUSE_STOCKS {
        catalog.require_unique_bindings(warehouse, &[tag])?;
    }
    let armory = dialog(CityFacilitySlot::Armory)?;
    catalog.require_unique_bindings(
        armory,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("sele"),
            fourcc!("unit"),
            fourcc!("cos0"),
            fourcc!("cos1"),
            fourcc!("cos2"),
            fourcc!("cos3"),
            fourcc!("ava0"),
            fourcc!("ava1"),
            fourcc!("ava2"),
            fourcc!("ava3"),
        ],
    )?;
    for binding in &ARMORY_ORDERS {
        let CityOrderId::MilitaryRecruit(category) = binding.order else {
            unreachable!("armory binding has a military recruitment order");
        };
        catalog.require_unique_bindings(armory, &[armory_button_tag(category)])?;
        for tag in [fourcc!("minu"), fourcc!("plus"), fourcc!("numb")] {
            catalog.require_control_under(armory, tag, &[binding.tag])?;
        }
    }
    let shipyard = dialog(CityFacilitySlot::Shipyard)?;
    catalog.require_unique_bindings(
        shipyard,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("sele"),
            fourcc!("titl"),
            fourcc!("snam"),
            fourcc!("desc"),
            fourcc!("spic"),
            fourcc!("fix0"),
            fourcc!("fix1"),
        ],
    )?;
    for binding in &SHIP_ORDERS {
        let CityOrderId::Ship(slot) = binding.order else {
            unreachable!("Shipyard binding has a ship order");
        };
        catalog.require_unique_bindings(shipyard, &[shipyard_button_tag(slot)])?;
        for tag in [fourcc!("minu"), fourcc!("plus"), fourcc!("numb")] {
            catalog.require_control_under(shipyard, tag, &[binding.tag])?;
        }
    }
    let university = dialog(CityFacilitySlot::University)?;
    catalog.require_unique_bindings(
        university,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("sele"),
            fourcc!("titl"),
            fourcc!("unit"),
            fourcc!("desc"),
            fourcc!("fix0"),
            fourcc!("fix1"),
            fourcc!("fix2"),
            fourcc!("fix3"),
            fourcc!("fix4"),
            fourcc!("cexp"),
            fourcc!("cpap"),
            fourcc!("cash"),
            fourcc!("aexp"),
            fourcc!("apap"),
            fourcc!("trea"),
        ],
    )?;
    for binding in &UNIVERSITY_ORDERS {
        let CityOrderId::CivilianRecruit(kind) = binding.order else {
            unreachable!("University binding has a civilian recruitment order");
        };
        catalog.require_unique_bindings(university, &[university_button_tag(kind)])?;
        for tag in [fourcc!("minu"), fourcc!("plus"), fourcc!("numb")] {
            catalog.require_control_under(university, tag, &[binding.tag])?;
        }
    }
    catalog.require_unique_bindings(
        &construction_dialog_view_id(),
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("okay"),
            fourcc!("cncl"),
            fourcc!("tex1"),
            fourcc!("tex2"),
            fourcc!("warn"),
            fourcc!("name"),
            fourcc!("cost"),
            fourcc!("capT"),
            fourcc!("or  "),
            fourcc!("buck"),
        ],
    )?;
    catalog.require_unique_bindings(
        &expansion_dialog_view_id(),
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("okay"),
            fourcc!("cncl"),
            fourcc!("name"),
            fourcc!("capT"),
            fourcc!("cost"),
            fourcc!("warn"),
        ],
    )?;
    Ok(())
}
