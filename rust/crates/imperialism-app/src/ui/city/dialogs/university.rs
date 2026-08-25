use super::*;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

pub(in crate::ui::city) struct UniversityRowUi {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) unit_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) preview: IndexedPicture,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityDialogUi {
    pub(in crate::ui::city) rows: Vec<UniversityRowUi>,
    pub(in crate::ui::city) orders: Vec<(CityOrderId, Entity)>,
    pub(in crate::ui::city) unit_name: Entity,
    pub(in crate::ui::city) description: Entity,
    pub(in crate::ui::city) labor_cost: Entity,
    pub(in crate::ui::city) material_cost: Entity,
    pub(in crate::ui::city) cash_cost: Entity,
    pub(in crate::ui::city) labor_available: Entity,
    pub(in crate::ui::city) material_available: Entity,
    pub(in crate::ui::city) treasury: Entity,
    pub(in crate::ui::city) tier_labels: [Entity; 3],
    pub(in crate::ui::city) details: Entity,
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
    bind_university_dialog(commands, root, tree, data);
}

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    data: UniversityDialogData,
) {
    let UniversityDialogData {
        available,
        rows: row_texts,
        resource_icons,
        details_base,
        details_image,
        normal_color,
        warning_color,
    } = data;
    let mut orders = Vec::new();
    let mut rows = Vec::new();
    for (spec, row_text) in UNIVERSITY_ROWS.iter().zip(row_texts) {
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
        orders.push((spec.binding.order, bound.quantity));
        let row_available = available[kind];
        bound.set_available(commands, row_available);
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert((
                CityRowChoice {
                    order: spec.binding.order,
                    selection: root,
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
        rows.push(UniversityRowUi {
            order: spec.binding.order,
            unit_name: row_text.unit_name,
            description: row_text.description,
            preview: row_text.preview,
        });
    }
    let dlog = tree.find(root, fourcc!("DLOG"));
    commands.entity(dlog).insert((
        ImageNode::new(details_image),
        UniversityDetailsVisual {
            base: details_base,
            resource_icons,
        },
    ));
    let tier_labels = [
        tree.find(root, fourcc!("fix2")),
        tree.find(root, fourcc!("fix3")),
        tree.find(root, fourcc!("fix4")),
    ];
    for &entity in &tier_labels {
        commands.entity(entity).insert(Visibility::Hidden);
    }
    let bind_text = |commands: &mut Commands, tag| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    };
    let unit_name = bind_text(commands, fourcc!("unit"));
    let description = bind_text(commands, fourcc!("desc"));
    let labor_cost = bind_text(commands, fourcc!("cexp"));
    let material_cost = bind_text(commands, fourcc!("cpap"));
    let cash_cost = bind_text(commands, fourcc!("cash"));
    let labor_available = bind_text(commands, fourcc!("aexp"));
    let material_available = bind_text(commands, fourcc!("apap"));
    let treasury = bind_text(commands, fourcc!("trea"));
    commands.entity(root).insert((
        CityRowSelection {
            order: CityOrderId::CivilianRecruit(CivilianUnitKind::Miner),
            normal_color,
            warning_color,
        },
        UniversityDialogUi {
            rows,
            orders,
            unit_name,
            description,
            labor_cost,
            material_cost,
            cash_cost,
            labor_available,
            material_available,
            treasury,
            tier_labels,
            details: dlog,
        },
    ));
}

pub(in crate::ui::city) fn refresh_university_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &UniversityDialogUi,
    selection: &CityRowSelection,
    assets: &mut RetailUiAssets,
    font_assets: &Assets<Font>,
    texts: &mut Query<&mut Text>,
    colors: &mut Query<&mut TextColor>,
    visibilities: &mut Query<&mut Visibility>,
    images: &mut Query<&mut ImageNode>,
    visuals: &Query<&UniversityDetailsVisual>,
) {
    let CityOrderId::CivilianRecruit(kind) = selection.order else {
        return;
    };
    for &(order, quantity) in &ui.orders {
        set_text(
            texts,
            quantity,
            game.city_order_quantity(nation, order).to_string(),
        );
    }
    let major = game.nations().major(nation);
    let city = &major.city;
    let row = ui
        .rows
        .iter()
        .find(|row| row.order == selection.order)
        .expect("University selection has a bound retail row");
    let spec = civilian_recruitment_spec(kind);
    let production = city.population.production_labor();
    let workforce_available = production.high.min(city.population.strength() / 4);
    let specialties = CIVILIAN_RESOURCE_SPECIALTIES[kind];
    let levels = &game.technology().city_capabilities_by_nation[nation]
        .university
        .requirement_levels;
    let maximum = specialties
        .iter()
        .flatten()
        .map(|resource| levels[*resource])
        .max()
        .unwrap_or(UniversityRequirementLevel::None);

    let normal = city_stock_color(false, selection);
    set_colored_text(texts, colors, ui.unit_name, row.unit_name.clone(), normal);
    set_colored_text(
        texts,
        colors,
        ui.description,
        row.description.clone(),
        normal,
    );
    set_colored_text(texts, colors, ui.labor_cost, 1.to_string(), normal);
    set_colored_text(
        texts,
        colors,
        ui.material_cost,
        spec.primary.per_unit().to_string(),
        normal,
    );
    set_colored_text(
        texts,
        colors,
        ui.cash_cost,
        format_currency(i32::from(spec.cash_per_unit)),
        normal,
    );
    set_colored_text(
        texts,
        colors,
        ui.labor_available,
        workforce_available.to_string(),
        city_stock_color(workforce_available < 1, selection),
    );
    set_colored_text(
        texts,
        colors,
        ui.material_available,
        city.stockpile[spec.primary.resource].to_string(),
        city_stock_color(
            city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
            selection,
        ),
    );
    set_colored_text(
        texts,
        colors,
        ui.treasury,
        format_currency(major.common.treasury),
        city_stock_color(
            major.common.treasury < i32::from(spec.cash_per_unit),
            selection,
        ),
    );
    for (index, &entity) in ui.tier_labels.iter().enumerate() {
        set_visible(visibilities, entity, (index as u8) < maximum.retail());
    }
    let mut text = RetailRasterTextPainter::from_preset(
        assets.fonts(),
        font_assets,
        RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        },
    )
    .expect("retail University custom-drawing text style");
    let visual = visuals
        .get(ui.details)
        .expect("University dialog has a details visual");
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
    let handle = images
        .get(ui.details)
        .expect("University dialog has a details image")
        .image
        .clone();
    assets.replace_image(&handle, picture.to_image(assets.default_dib_palette()));
}
