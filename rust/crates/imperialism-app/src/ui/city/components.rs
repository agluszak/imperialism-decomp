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

#[derive(Component)]
pub(in crate::ui::city) struct CityScreenNeedsSync;

#[derive(Component)]
pub(in crate::ui::city) struct CityDialogsNeedRestore;

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

#[derive(Component)]
pub(in crate::ui::city) struct CityDialogNeedsSync;

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
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) fill: Entity,
    pub(in crate::ui::city) maximum: Entity,
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
pub(in crate::ui::city) struct UniversityPreview {
    pub(in crate::ui::city) dialog: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct UniversityRequirementIcon {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) row: usize,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct UniversityRequirementValue {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) row: usize,
    pub(in crate::ui::city) level: u8,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct UniversityTierLabel {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) level: u8,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) enum UniversityWarningKind {
    Paper,
    Workforce,
    Treasury,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct UniversityWarningValue {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) kind: UniversityWarningKind,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
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

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ShipyardDetailPicture {
    pub(in crate::ui::city) dialog: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ShipyardMaterialPicture {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) index: usize,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ShipyardMaterialAmount {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) index: usize,
    pub(in crate::ui::city) available: bool,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct ShipyardStatValue {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) index: usize,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum CityValue {
    LaborLow,
    LaborMedium,
    LaborHigh,
    LaborAvailable,
    PowerAvailable,
    Stock(ResourceKind),
    WarehouseFishAndLivestock,
    Treasury,
    PredictedNeed(ResourceKind),
    OrderQuantity(CityOrderId),
    ArmoryOrderQuantity(MilitaryRecruitmentCategory),
    UniversityOrderQuantity(CivilianUnitKind),
    ShipyardOrderQuantity(ShipOrderSlot),
    LaborIndicator,
    StockIndicator(ResourceKind, i16),
    AvailableStockIndicator(ResourceKind, i16),
    AvailableCombinedStockIndicator(ResourceKind, ResourceKind, i16),
    AvailableBudgetIndicator(i32),
    TrainingLaborIndicator(TrainingLevel),
    BuildingCapacity(CityFacilitySlot),
    RegionalCapacity,
    OwnedRegionCount,
    ArmoryUnitKind,
    ArmoryWorkforceCost,
    ArmoryPrimaryCost,
    ArmorySecondaryCost,
    ArmoryCashCost,
    ArmoryWorkforceAvailable,
    ArmoryPrimaryAvailable,
    ArmorySecondaryAvailable,
    ArmoryTreasuryAvailable,
    UniversityUnitName,
    UniversityDescription,
    UniversityWorkforceCost,
    UniversityPaperCost,
    UniversityCashCost,
    UniversityWorkforceAvailable,
    UniversityPaperAvailable,
    ShipyardName,
    ShipyardDescription,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityValueBinding {
    pub(in crate::ui::city) dialog: Option<Entity>,
    pub(in crate::ui::city) value: CityValue,
}

#[derive(Component)]
pub(in crate::ui::city) struct RetailNumberTemplate(pub(in crate::ui::city) String);

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityExpansionIndicator {
    pub(in crate::ui::city) dialog: Entity,
    pub(in crate::ui::city) slot: CityFacilitySlot,
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
