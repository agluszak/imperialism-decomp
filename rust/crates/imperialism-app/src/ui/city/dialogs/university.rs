use super::*;
use crate::ui::retail_raster::IndexedRasterExt;
use imperialism_formats::RetailTextStylePreset;

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
    pub(in crate::ui::city) rows: [UniversityRowText; UNIVERSITY_ROWS.len()],
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

/// Development-yield number of one specialty/tier cell, drawn as a Bevy text
/// child over DLOG. The grid is at most 4 specialties × 3 levels.
#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct UniversityYieldText {
    row_index: usize,
    level: i32,
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
    root: Entity,
    tree: &RetailTree,
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
        rows: UNIVERSITY_ROWS.map(|row| {
            let kind = row.civilian_kind();
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
    bind_university_dialog(commands, assets, root, tree, data);
}

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
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
    for (spec, row_text) in UNIVERSITY_ROWS.iter().zip(rows) {
        let kind = spec.civilian_kind();
        let button = tree.find(root, spec.button_tag);
        let bound = bind_city_order_row(
            commands,
            root,
            tree,
            spec.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
            Some(root),
        );
        let row_available = available[kind];
        bound.set_available(commands, row_available);
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert((
                CityRowChoice {
                    order: spec.binding.order,
                    selection: root,
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
    let dlog = tree.find(root, fourcc!("DLOG"));
    commands.entity(dlog).insert((
        ImageNode::new(details_image),
        UniversityDetailsVisual {
            base: details_base,
            resource_icons,
        },
    ));
    // `TUniversityView::DoStartup` installs its 10-point (Book Antiqua) style on
    // the yield numbers; raster compositing is kept only for the preview picture
    // and resource icons.
    let (yield_font, yield_layout, yield_line_height, _) = assets
        .text_style(RetailTextStylePreset::built(10, -2))
        .expect("retail University yield text style");
    for row_index in 0..4 {
        for level in 1..=3 {
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px((level * 40 + 39) as f32),
                    top: px((row_index as i32 * 25 + 289 - 11) as f32),
                    width: px(36.0),
                    height: px(14.0),
                    ..default()
                },
                Text::new(""),
                yield_font.clone(),
                yield_layout,
                yield_line_height,
                TextColor(normal_color),
                UniversityYieldText { row_index, level },
                Visibility::Hidden,
                Pickable::IGNORE,
                ChildOf(dlog),
            ));
        }
    }
    let tier_labels = [
        tree.find(root, fourcc!("fix2")),
        tree.find(root, fourcc!("fix3")),
        tree.find(root, fourcc!("fix4")),
    ];
    for (index, entity) in tier_labels.into_iter().enumerate() {
        commands
            .entity(entity)
            .insert((Visibility::Hidden, UniversityDisplay::TierLabel(index)));
    }
    let bind_text = |commands: &mut Commands, tag, display: UniversityDisplay| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert((Text::new(""), display));
    };
    bind_text(commands, fourcc!("unit"), UniversityDisplay::UnitName);
    bind_text(commands, fourcc!("desc"), UniversityDisplay::Description);
    bind_text(commands, fourcc!("cexp"), UniversityDisplay::LaborCost);
    bind_text(commands, fourcc!("cpap"), UniversityDisplay::MaterialCost);
    bind_text(commands, fourcc!("cash"), UniversityDisplay::CashCost);
    bind_text(commands, fourcc!("aexp"), UniversityDisplay::LaborAvailable);
    bind_text(
        commands,
        fourcc!("apap"),
        UniversityDisplay::MaterialAvailable,
    );
    bind_text(commands, fourcc!("trea"), UniversityDisplay::Treasury);
    commands.entity(root).insert(CityRowSelection {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Miner),
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn sync_university_details(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    mut image_assets: ResMut<Assets<Image>>,
    selections: Query<Ref<CityRowSelection>>,
    rows: Query<(&CityRowChoice, &UniversityRowAssets)>,
    mut texts: Query<(&UniversityDisplay, &mut Text), Without<ImageNode>>,
    mut text_colors: Query<(&UniversityDisplay, &mut TextColor), Without<ImageNode>>,
    mut visibilities: Query<(&UniversityDisplay, &mut Visibility)>,
    details: Query<(&UniversityDetailsVisual, &ImageNode)>,
    mut yields: Query<(&UniversityYieldText, &mut Text, &mut Visibility), Without<ImageNode>>,
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
    for (visual, image_node) in &details {
        let mut picture = visual.base.clone();
        picture.blit_keyed_at(&row.preview, IVec2::new(0x7c, 0x5c), 0x10);
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
        }
        if let Some(mut image) = image_assets.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
        }
    }
    for (yield_text, mut text, mut visibility) in &mut yields {
        let Some(resource) = specialties.get(yield_text.row_index).copied().flatten() else {
            *visibility = Visibility::Hidden;
            continue;
        };
        if i32::from(levels[resource].retail()) < yield_text.level {
            *visibility = Visibility::Hidden;
            continue;
        }
        *visibility = Visibility::Inherited;
        text.0 = resource_development_yield(
            resource,
            u8::try_from(yield_text.level).expect("university tier level fits in u8"),
        )
        .to_string();
    }
}
