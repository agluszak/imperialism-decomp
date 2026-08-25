use super::*;
use crate::RetailFonts;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

#[derive(Component)]
pub(in crate::ui::city) struct UniversityRowAssets {
    unit_name: String,
    description: String,
    preview: IndexedPicture,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum UniversityDisplay {
    UnitName,
    Description,
    LaborCost,
    MaterialCost,
    CashCost,
    LaborAvailable,
    MaterialAvailable,
    Treasury,
    TierLabel(usize),
}

pub(in crate::ui::city) struct UniversityRowText {
    pub(in crate::ui::city) unit_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) preview: IndexedPicture,
}

pub(in crate::ui::city) struct UniversityDialogData {
    pub(in crate::ui::city) available: CivilianUnitTable<bool>,
    pub(in crate::ui::city) rows: [UniversityRowText; UNIVERSITY_KINDS.len()],
    pub(in crate::ui::city) resource_icons: IndexedPicture,
    pub(in crate::ui::city) details_base: IndexedPicture,
    pub(in crate::ui::city) details_image: Handle<Image>,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityDetailsVisual {
    base: IndexedPicture,
    resource_icons: IndexedPicture,
}

pub(in crate::ui::city) const fn university_preview_picture(kind: CivilianUnitKind) -> i16 {
    match kind {
        CivilianUnitKind::Miner => 402,
        CivilianUnitKind::Prospector => 403,
        CivilianUnitKind::Farmer => 401,
        CivilianUnitKind::Forester => 406,
        CivilianUnitKind::Engineer => 400,
        CivilianUnitKind::Rancher => 407,
        CivilianUnitKind::Fisherman => 405,
        CivilianUnitKind::Developer => 404,
        CivilianUnitKind::Driller => 408,
    }
}

pub(in crate::ui::city) fn configure_university_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: &generated::Univ9210,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let details_base = assets
        .indexed_picture(PictureId::new(9900))
        .expect("retail University dialog picture must load");
    let details_image = assets.add_image(details_base.to_image(assets.default_dib_palette()));
    let data = UniversityDialogData {
        available: state.technology().city_capabilities_by_nation[nation]
            .university
            .available,
        rows: UNIVERSITY_KINDS.map(|kind| {
            UniversityRowText {
                // Retail `TUniversityView::SetUnit` pre-increments the 0-based
                // recruitment category once and reuses that 1-based index for
                // both `0x2718` (name) and `0x2751` (description).
                unit_name: assets
                    .string(0x2718, i16::from(kind.retail()) + 1)
                    .expect("retail civilian name"),
                description: assets
                    .string(0x2751, i16::from(kind.retail()) + 1)
                    .expect("retail civilian description"),
                preview: assets
                    .indexed_picture(PictureId::new(university_preview_picture(kind)))
                    .expect("retail University preview picture must load"),
            }
        }),
        resource_icons: assets
            .indexed_picture(PictureId::new(750))
            .expect("retail University resource icons must load"),
        details_base,
        details_image,
        normal_color: assets.palette_color(0xd2),
        warning_color: assets.palette_color(0xcb),
    };
    bind_university_dialog(commands, ui, data);
}

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    ui: &generated::Univ9210,
    data: UniversityDialogData,
) {
    let UniversityDialogData {
        available,
        rows,
        resource_icons,
        details_base,
        details_image,
        normal_color,
        warning_color,
    } = data;
    let row_controls = [
        (ui.clu0, ui.clu0_minu, ui.clu0_plus, ui.num0_numb, ui.civ0),
        (ui.clu1, ui.clu1_minu, ui.clu1_plus, ui.num1_numb, ui.civ1),
        (ui.clu2, ui.clu2_minu, ui.clu2_plus, ui.num2_numb, ui.civ2),
        (ui.clu3, ui.clu3_minu, ui.clu3_plus, ui.num3_numb, ui.civ3),
        (ui.clu4, ui.clu4_minu, ui.clu4_plus, ui.num4_numb, ui.civ4),
        (ui.clu5, ui.clu5_minu, ui.clu5_plus, ui.num5_numb, ui.civ5),
        (ui.clu8, ui.clu8_minu, ui.clu8_plus, ui.num8_numb, ui.civ8),
    ];
    for (kind, (row, decrease, increase, quantity, button), row_text) in UNIVERSITY_KINDS
        .into_iter()
        .zip(row_controls)
        .zip(rows)
        .map(|((kind, controls), text)| (kind, controls, text))
    {
        let order = CityOrderId::CivilianRecruit(kind);
        let bound = bind_city_order_row(
            commands,
            order,
            row,
            decrease,
            increase,
            quantity,
            1,
            Some(ui.root),
        );
        let row_available = available[kind];
        bound.set_available(commands, row_available);
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert((
                CityRowChoice {
                    order,
                    selection: ui.root,
                },
                UniversityRowAssets {
                    unit_name: row_text.unit_name,
                    description: row_text.description,
                    preview: row_text.preview,
                },
                if row_available {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                },
            ));
            button_commands.observe(on_city_row_selected);
            if row_available {
                button_commands.remove::<InteractionDisabled>();
            } else {
                button_commands.insert(InteractionDisabled);
            }
        }
        commands.entity(bound.quantity).insert(InteractionDisabled);
    }
    commands.entity(ui.dlog).insert((
        ImageNode::new(details_image),
        UniversityDetailsVisual {
            base: details_base,
            resource_icons,
        },
    ));
    for (index, entity) in [ui.fix2, ui.fix3, ui.fix4].into_iter().enumerate() {
        commands
            .entity(entity)
            .insert((Visibility::Hidden, UniversityDisplay::TierLabel(index)));
    }
    for (entity, display) in [
        (ui.unit, UniversityDisplay::UnitName),
        (ui.desc, UniversityDisplay::Description),
        (ui.cexp, UniversityDisplay::LaborCost),
        (ui.cpap, UniversityDisplay::MaterialCost),
        (ui.cash, UniversityDisplay::CashCost),
        (ui.aexp, UniversityDisplay::LaborAvailable),
        (ui.apap, UniversityDisplay::MaterialAvailable),
        (ui.trea, UniversityDisplay::Treasury),
    ] {
        commands.entity(entity).insert((Text::new(""), display));
    }
    commands.entity(ui.root).insert(CityRowSelection {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Miner),
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn sync_university_details(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut image_assets: ResMut<Assets<Image>>,
    selections: Query<Ref<CityRowSelection>>,
    rows: Query<(&CityRowChoice, &UniversityRowAssets)>,
    mut texts: Query<(&UniversityDisplay, &mut Text), Without<ImageNode>>,
    mut text_colors: Query<(&UniversityDisplay, &mut TextColor), Without<ImageNode>>,
    mut visibilities: Query<(&UniversityDisplay, &mut Visibility)>,
    details: Query<(&UniversityDetailsVisual, &ImageNode)>,
) {
    let Some(selection) = selections
        .iter()
        .find(|selection| matches!(selection.order, CityOrderId::CivilianRecruit(_)))
    else {
        return;
    };
    if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
        return;
    }
    let CityOrderId::CivilianRecruit(kind) = selection.order else {
        return;
    };
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let row = rows
        .iter()
        .find(|(choice, _)| choice.order == selection.order)
        .map(|(_, assets)| assets)
        .expect("University selection has a bound retail row");
    let spec = civilian_recruitment_spec(kind);
    let production = city.population.production_labor();
    let workforce_available = production.high.min(city.population.strength() / 4);
    let specialties = CIVILIAN_RESOURCE_SPECIALTIES[kind];
    let levels = &session.game.technology().city_capabilities_by_nation[nation]
        .university
        .requirement_levels;
    let maximum = specialties
        .iter()
        .flatten()
        .map(|resource| levels[*resource])
        .max()
        .unwrap_or(UniversityRequirementLevel::None);

    for (display, mut text) in &mut texts {
        match *display {
            UniversityDisplay::UnitName => text.0.clone_from(&row.unit_name),
            UniversityDisplay::Description => text.0.clone_from(&row.description),
            UniversityDisplay::LaborCost => text.0 = 1.to_string(),
            UniversityDisplay::MaterialCost => text.0 = spec.primary.per_unit().to_string(),
            UniversityDisplay::CashCost => text.0 = format_currency(i32::from(spec.cash_per_unit)),
            UniversityDisplay::LaborAvailable => text.0 = workforce_available.to_string(),
            UniversityDisplay::MaterialAvailable => {
                text.0 = city.stockpile[spec.primary.resource].to_string()
            }
            UniversityDisplay::Treasury => text.0 = format_currency(major.common.treasury),
            _ => {}
        }
    }
    for (display, mut color) in &mut text_colors {
        let insufficient = match display {
            UniversityDisplay::MaterialAvailable => {
                city.stockpile[spec.primary.resource] < spec.primary.per_unit()
            }
            UniversityDisplay::LaborAvailable => workforce_available < 1,
            UniversityDisplay::Treasury => major.common.treasury < i32::from(spec.cash_per_unit),
            _ => continue,
        };
        color.0 = city_stock_color(insufficient, &selection);
    }
    for (display, mut visibility) in &mut visibilities {
        *visibility = match *display {
            UniversityDisplay::TierLabel(index) => {
                if (index as u8) < maximum.retail() {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                }
            }
            _ => continue,
        };
    }
    let mut text = RetailRasterTextPainter::from_preset(
        &fonts,
        &font_assets,
        RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        },
    )
    .expect("retail University custom-drawing text style");
    for (visual, image_node) in &details {
        let mut picture = visual.base.clone();
        picture.blit_keyed_at(&row.preview, IVec2::new(0x7c, 0x5c), 0x10);
        let mut running_max = UniversityRequirementLevel::None;
        for (row_index, resource) in specialties.into_iter().enumerate() {
            let Some(resource) = resource else {
                continue;
            };
            let source_left = i32::from(resource.retail()) * 20;
            picture.blit_keyed(
                &visual.resource_icons,
                IRect::new(source_left, 0, source_left + 20, 24),
                IVec2::new(25, 274 + row_index as i32 * 25),
                0x10,
            );
            running_max = running_max.max(levels[resource]);
            for level in 1..=running_max.retail() {
                text.draw(
                    &mut picture,
                    IVec2::new(i32::from(level) * 40 + 39, row_index as i32 * 25 + 289),
                    &resource_development_yield(resource, level).to_string(),
                    0xd2,
                );
            }
        }
        if let Some(mut image) = image_assets.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
        }
    }
}
