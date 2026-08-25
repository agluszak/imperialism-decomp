use super::*;
use crate::RetailFonts;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

struct UniversityRow {
    order: CityOrderId,
    controls: CityOrderRow,
    unit_name: String,
    description: String,
    preview: IndexedPicture,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityView {
    rows: Vec<UniversityRow>,
    unit_name: Entity,
    description: Entity,
    labor_cost: Entity,
    material_cost: Entity,
    cash_cost: Entity,
    labor_available: Entity,
    material_available: Entity,
    treasury: Entity,
    tier_labels: [Entity; 3],
    details: Entity,
    details_base: IndexedPicture,
    resource_icons: IndexedPicture,
    normal_color: Color,
    warning_color: Color,
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
        rows: row_text,
        resource_icons,
        details_base,
        details_image,
        normal_color,
        warning_color,
    } = data;
    let mut rows = Vec::new();
    for (spec, row_text) in UNIVERSITY_ROWS.iter().zip(row_text) {
        let kind = spec.civilian_kind();
        let button = tree.find(root, spec.button_tag);
        let controls = bind_recruitment_order_row(commands, root, tree, spec.binding, root);
        let row_available = available[kind];
        controls.set_available(commands, row_available);
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
        commands
            .entity(controls.quantity)
            .insert(InteractionDisabled);
        rows.push(UniversityRow {
            order: spec.binding.order,
            controls,
            unit_name: row_text.unit_name,
            description: row_text.description,
            preview: row_text.preview,
        });
    }
    let dlog = tree.find(root, fourcc!("DLOG"));
    commands.entity(dlog).insert(ImageNode::new(details_image));
    let tier_labels = [
        tree.find(root, fourcc!("fix2")),
        tree.find(root, fourcc!("fix3")),
        tree.find(root, fourcc!("fix4")),
    ];
    for entity in tier_labels {
        commands.entity(entity).insert(Visibility::Hidden);
    }
    let bind_text = |commands: &mut Commands, tag| {
        let entity = tree.find(root, tag);
        commands
            .entity(entity)
            .insert((Text::new(""), TextColor(normal_color)));
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
        UniversityView {
            rows,
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
            details_base,
            resource_icons,
            normal_color,
            warning_color,
        },
        CityOrderSelection(CityOrderId::CivilianRecruit(CivilianUnitKind::Miner)),
    ));
}

pub(in crate::ui::city) fn sync_university_details(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut image_assets: ResMut<Assets<Image>>,
    views: Query<(&UniversityView, Ref<CityOrderSelection>)>,
    mut texts: Query<&mut Text>,
    mut colors: Query<&mut TextColor>,
    mut visibilities: Query<&mut Visibility>,
    details: Query<&ImageNode>,
) {
    for (view, selection) in &views {
        if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
            continue;
        }
        let CityOrderId::CivilianRecruit(kind) = selection.0 else {
            continue;
        };
        let nation = session.active_major_nation();
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let row = view
            .rows
            .iter()
            .find(|row| row.order == selection.0)
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

        for row in &view.rows {
            project_order_quantity(
                &session,
                &mut texts,
                row.controls,
                row.order,
                "university order quantity remains bound",
            );
        }
        set_bound_text(
            &mut texts,
            view.unit_name,
            row.unit_name.clone(),
            "university unit name remains bound",
        );
        set_bound_text(
            &mut texts,
            view.description,
            row.description.clone(),
            "university description remains bound",
        );
        set_bound_text(
            &mut texts,
            view.labor_cost,
            1.to_string(),
            "university labor cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.material_cost,
            spec.primary.per_unit().to_string(),
            "university material cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.cash_cost,
            format_currency(i32::from(spec.cash_per_unit)),
            "university cash cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.labor_available,
            workforce_available.to_string(),
            "university labor available remains bound",
        );
        set_bound_text(
            &mut texts,
            view.material_available,
            city.stockpile[spec.primary.resource].to_string(),
            "university material available remains bound",
        );
        set_bound_text(
            &mut texts,
            view.treasury,
            format_currency(major.common.treasury),
            "university treasury remains bound",
        );
        let color = |warning| city_stock_color(warning, view.warning_color, view.normal_color);
        set_bound_text_color(
            &mut colors,
            view.material_available,
            color(city.stockpile[spec.primary.resource] < spec.primary.per_unit()),
            "university material available remains bound",
        );
        set_bound_text_color(
            &mut colors,
            view.labor_available,
            color(workforce_available < 1),
            "university labor available remains bound",
        );
        set_bound_text_color(
            &mut colors,
            view.treasury,
            color(major.common.treasury < i32::from(spec.cash_per_unit)),
            "university treasury remains bound",
        );
        for (index, entity) in view.tier_labels.into_iter().enumerate() {
            set_bound_visible(
                &mut visibilities,
                entity,
                (index as u8) < maximum.retail(),
                "university tier label remains bound",
            );
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
        let image_node = details
            .get(view.details)
            .expect("university details remain bound");
        let mut picture = view.details_base.clone();
        picture.blit_keyed_at(&row.preview, IVec2::new(0x7c, 0x5c), 0x10);
        let mut running_max = UniversityRequirementLevel::None;
        for (row_index, resource) in specialties.into_iter().enumerate() {
            let Some(resource) = resource else {
                continue;
            };
            let source_left = i32::from(resource.retail()) * 20;
            picture.blit_keyed(
                &view.resource_icons,
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
        *image_assets
            .get_mut(&image_node.image)
            .expect("university details image remains bound") =
            picture.to_image(retail.assets().default_dib_palette());
    }
}
