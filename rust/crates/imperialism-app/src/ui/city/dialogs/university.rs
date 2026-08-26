use super::*;
use crate::RetailFonts;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

/// One University row's button and the retail unit facts it selects.
pub(in crate::ui::city) struct UniversityRowView {
    button: Entity,
    quantity: Entity,
    unit_name: String,
    description: String,
    preview: IndexedPicture,
}

/// Root view of the University dialog.
#[derive(Component)]
pub(in crate::ui::city) struct UniversityView {
    selected: CivilianUnitKind,
    rows: [UniversityRowView; UNIVERSITY_ROWS.len()],
    unit: Entity,
    description: Entity,
    costs: [Entity; 3],
    available: [Entity; 3],
    tier_labels: [Entity; 3],
    details: Entity,
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
    let available = state.technology().city_capabilities_by_nation[nation]
        .university
        .available;
    let rows = UNIVERSITY_ROWS.map(|row| {
        let kind = row.civilian_kind();
        let bound = bind_city_order_row(
            commands,
            root,
            tree,
            row.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
        );
        for arrow in [bound.decrease, bound.increase] {
            commands.entity(arrow).observe(
                move |_: On<Activate>, mut views: Query<&mut UniversityView>| {
                    if let Ok(mut view) = views.get_mut(root) {
                        view.selected = kind;
                    }
                },
            );
        }
        let button = tree.find(root, row.button_tag);
        let row_available = available[kind];
        bound.set_available(commands, row_available);
        let mut button_commands = commands.entity(button);
        button_commands.insert(if row_available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
        button_commands.observe(
            move |change: On<ValueChange<bool>>, mut views: Query<&mut UniversityView>| {
                if change.value
                    && let Ok(mut view) = views.get_mut(root)
                {
                    view.selected = kind;
                }
            },
        );
        if row_available {
            button_commands.remove::<InteractionDisabled>();
        } else {
            button_commands.insert(InteractionDisabled);
        }
        commands.entity(bound.quantity).insert(InteractionDisabled);
        UniversityRowView {
            button,
            quantity: bound.quantity,
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
    });
    let resource_icons = assets
        .indexed_picture(PictureId::new(750))
        .expect("retail University resource icons must load");
    let details_image = assets.add_image(details_base.to_image(assets.default_dib_palette()));
    let details = tree.find(root, fourcc!("DLOG"));
    commands.entity(details).insert((
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
    for entity in &tier_labels {
        commands.entity(*entity).insert(Visibility::Hidden);
    }
    let mut bind_text = |tag| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    };
    let unit = bind_text(fourcc!("unit"));
    let description = bind_text(fourcc!("desc"));
    let costs = [
        bind_text(fourcc!("cexp")),
        bind_text(fourcc!("cpap")),
        bind_text(fourcc!("cash")),
    ];
    let available = [
        bind_text(fourcc!("aexp")),
        bind_text(fourcc!("apap")),
        bind_text(fourcc!("trea")),
    ];
    commands.entity(root).insert(UniversityView {
        selected: CivilianUnitKind::Miner,
        rows,
        unit,
        description,
        costs,
        available,
        tier_labels,
        details,
    });
}

pub(in crate::ui::city) fn render_university_dialog(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut image_assets: ResMut<Assets<Image>>,
    assets: RetailUiAssets,
    views: Query<Ref<UniversityView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut visibilities: Query<&mut Visibility>,
    details: Query<(&UniversityDetailsVisual, &ImageNode)>,
    checked: Query<Has<Checked>>,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for (row, view_row) in UNIVERSITY_ROWS.iter().zip(&view.rows) {
            let selected = row.civilian_kind() == view.selected;
            let checked = checked.get(view_row.button).unwrap_or(false);
            if selected && !checked {
                commands.entity(view_row.button).insert(Checked);
            } else if !selected && checked {
                commands.entity(view_row.button).remove::<Checked>();
            }
            texts
                .get_mut(view_row.quantity)
                .expect("bound University order quantity")
                .0 = session
                .game
                .city_order_quantity(nation, row.binding.order)
                .to_string();
        }
        let row = UNIVERSITY_ROWS
            .iter()
            .zip(&view.rows)
            .find(|(row, _)| row.civilian_kind() == view.selected)
            .map(|(_, row)| row)
            .expect("University selection has a bound retail row");
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let spec = civilian_recruitment_spec(view.selected);
        let production = city.population.production_labor();
        let workforce_available = production.high.min(city.population.strength() / 4);
        let specialties = CIVILIAN_RESOURCE_SPECIALTIES[view.selected];
        let levels = &session.game.technology().city_capabilities_by_nation[nation]
            .university
            .requirement_levels;
        let maximum = specialties
            .iter()
            .flatten()
            .map(|resource| levels[*resource])
            .max()
            .unwrap_or(UniversityRequirementLevel::None);
        texts
            .get_mut(view.unit)
            .expect("bound University unit name")
            .0
            .clone_from(&row.unit_name);
        texts
            .get_mut(view.description)
            .expect("bound University description")
            .0
            .clone_from(&row.description);
        let values = [
            1.to_string(),
            spec.primary.per_unit().to_string(),
            format_currency(i32::from(spec.cash_per_unit)),
            workforce_available.to_string(),
            city.stockpile[spec.primary.resource].to_string(),
            format_currency(major.common.treasury),
        ];
        for (entity, value) in view.costs.iter().chain(&view.available).zip(&values) {
            texts
                .get_mut(*entity)
                .expect("bound University detail")
                .0
                .clone_from(value);
        }
        let insufficiencies = [
            workforce_available < 1,
            city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
            major.common.treasury < i32::from(spec.cash_per_unit),
        ];
        for (entity, insufficient) in view.available.iter().zip(&insufficiencies) {
            text_colors
                .get_mut(*entity)
                .expect("bound University availability")
                .0 = if *insufficient {
                warning_color
            } else {
                normal_color
            };
        }
        for (entity, index) in view.tier_labels.iter().zip(0..3) {
            *visibilities
                .get_mut(*entity)
                .expect("bound University tier label") = if (index as u8) < maximum.retail() {
                Visibility::Visible
            } else {
                Visibility::Hidden
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
        let Ok((visual, image_node)) = details.get(view.details) else {
            continue;
        };
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
