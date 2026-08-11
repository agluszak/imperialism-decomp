use super::*;

#[derive(Clone)]
pub(in crate::ui::city) struct CityBuildingHitRegion {
    pub(in crate::ui::city) origin: IVec2,
    pub(in crate::ui::city) draw_order: u8,
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) dialog: ScopedViewId,
    pub(in crate::ui::city) mask: CityBuildingHitMask,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityCanvas {
    pub(in crate::ui::city) buildings: Vec<CityBuildingHitRegion>,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityScreenRoot;

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityBuildingPicture {
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingActionAnimation {
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) frame_count: u8,
    pub(in crate::ui::city) frame_size: [i32; 2],
    pub(in crate::ui::city) frame: u8,
    pub(in crate::ui::city) timer: Timer,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityBuildingDialog {
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) window: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityDialogWindow {
    pub(in crate::ui::city) dialog: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityDialogCaption {
    pub(in crate::ui::city) window: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityDialogClose {
    pub(in crate::ui::city) dialog: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityExpansionOpen {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityBuildingChangeDialog;

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityBuildingChangeChoice {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) accept: bool,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityOrderAdjust {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) delta: i16,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityIndustryAmountBar {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) nation: MajorNationId,
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ArmorySelection {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ArmoryRowChoice {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct UniversitySelection {
    pub(in crate::ui::city) kind: CivilianUnitKind,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityRowChoice {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) kind: CivilianUnitKind,
    pub(in crate::ui::city) unit_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) preview: Handle<Image>,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ShipyardSelection {
    pub(in crate::ui::city) slot: ShipOrderSlot,
}

#[derive(Component)]
pub(in crate::ui::city) struct ShipyardRowChoice {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) slot: ShipOrderSlot,
    pub(in crate::ui::city) ship_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) picture: Handle<Image>,
    pub(in crate::ui::city) materials: Vec<ShipyardMaterialData>,
    pub(in crate::ui::city) stats: [i16; 6],
}

pub(in crate::ui::city) fn format_retail_value(template: &str, value: &str) -> String {
    if template.contains("[1: number]") {
        template.replace("[1: number]", value)
    } else if template.contains("[1:number]") {
        template.replace("[1:number]", value)
    } else {
        panic!("retail City number template has no first-number token");
    }
}

pub(in crate::ui::city) fn format_retail_number(template: &str, value: i16) -> String {
    format_retail_value(template, &value.to_string())
}

pub(in crate::ui::city) fn format_currency(value: i32) -> String {
    let negative = value < 0;
    let digits = i64::from(value).abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if negative {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
    }
}
