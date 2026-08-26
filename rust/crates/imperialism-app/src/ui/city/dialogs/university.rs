use super::*;
use crate::ui::retail_raster::IndexedRasterExt;

/// One University row's button and quantity marker.
struct UniversityRowView {
    button: Entity,
    quantity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityYieldText;

/// Root view of the University dialog. The detail pane is one retail picture
/// redrawn from the selected kind.
#[derive(Component)]
pub(in crate::ui::city) struct UniversityView {
    selected: CivilianUnitKind,
    rows: [UniversityRowView; UNIVERSITY_CONTROLS.len()],
    unit: Entity,
    description: Entity,
    costs: [Entity; 3],
    available: [Entity; 3],
    tier_labels: [Entity; 3],
    details: Entity,
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
    let available = state.technology().city_capabilities_by_nation[nation]
        .university
        .available;
    let rows = std::array::from_fn(|index| {
        let (kind, order_tag, button_tag) = UNIVERSITY_CONTROLS[index];
        let bound = bind_recruitment_order_row(
            commands,
            root,
            tree,
            CityOrderBinding {
                order: CityOrderId::CivilianRecruit(kind),
                tag: order_tag,
            },
        );
        for tag in [fourcc!("minu"), fourcc!("plus")] {
            commands.entity(tree.find(bound.row, tag)).observe(
                move |_: On<Activate>, mut views: Query<&mut UniversityView>| {
                    if let Ok(mut view) = views.get_mut(root) {
                        view.selected = kind;
                    }
                },
            );
        }
        let button = tree.find(root, button_tag);
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
        }
    });
    let dlog = tree.find(root, fourcc!("DLOG"));
    let details_base = assets
        .indexed_picture(PictureId::new(9900))
        .expect("retail University dialog picture must load");
    let details_image = assets.add_image(details_base.to_image(assets.default_dib_palette()));
    commands.entity(dlog).insert(ImageNode::new(details_image));
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
    let tier_labels = [
        tree.find(root, fourcc!("fix2")),
        tree.find(root, fourcc!("fix3")),
        tree.find(root, fourcc!("fix4")),
    ];
    for entity in &tier_labels {
        commands.entity(*entity).insert(Visibility::Hidden);
    }
    commands.entity(root).insert(UniversityView {
        selected: CivilianUnitKind::Miner,
        rows,
        unit,
        description,
        costs,
        available,
        tier_labels,
        details: dlog,
    });
}

pub(in crate::ui::city) fn render_university_dialog(
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    views: Query<Ref<UniversityView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut visibilities: Query<&mut Visibility>,
    mut images: Query<&mut ImageNode>,
    checked: Query<Has<Checked>>,
    yield_texts: Query<Entity, With<UniversityYieldText>>,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for ((kind, _, _), view_row) in UNIVERSITY_CONTROLS.iter().zip(&view.rows) {
            sync_recruitment_row(
                &mut commands,
                &checked,
                &mut texts,
                view_row.button,
                *kind == view.selected,
                view_row.quantity,
                session
                    .game
                    .city_order_quantity(nation, CityOrderId::CivilianRecruit(*kind))
                    .to_string(),
            );
        }
        let kind = view.selected;
        let major = session.game.nations().major(nation);
        let city = &major.city;
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
        let unit_name = assets
            .string(0x2718, i16::from(kind.retail()) + 1)
            .expect("retail civilian name");
        let description = assets
            .string(0x2751, i16::from(kind.retail()) + 1)
            .expect("retail civilian description");
        texts
            .get_mut(view.unit)
            .expect("bound University unit name")
            .0
            .clone_from(&unit_name);
        texts
            .get_mut(view.description)
            .expect("bound University description")
            .0
            .clone_from(&description);
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
        let mut picture = assets
            .indexed_picture(PictureId::new(9900))
            .expect("retail University dialog picture must load");
        let preview = assets
            .indexed_picture(PictureId::new(university_preview_picture(kind)))
            .expect("retail University preview picture must load");
        picture.blit_keyed_at(&preview, IVec2::new(0x7c, 0x5c), 0x10);
        let icons = assets
            .indexed_picture(PictureId::new(750))
            .expect("retail University resource icons must load");
        let mut running_max = UniversityRequirementLevel::None;
        for entity in &yield_texts {
            commands.entity(entity).despawn();
        }
        let (font, layout, line_height, _) = assets
            .text_style(RetailTextStylePreset::explicit(3, 0, 10, -2))
            .expect("retail University yield text style");
        for (row_index, resource) in specialties.into_iter().enumerate() {
            let Some(resource) = resource else {
                continue;
            };
            let source_left = i32::from(resource.retail()) * 20;
            picture.blit_keyed(
                &icons,
                IRect::new(source_left, 0, source_left + 20, 24),
                IVec2::new(25, 274 + row_index as i32 * 25),
                0x10,
            );
            running_max = running_max.max(levels[resource]);
            for level in 1..=running_max.retail() {
                commands.spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(i32::from(level) * 40 + 39),
                        top: px(row_index as i32 * 25 + 289 - 11),
                        ..default()
                    },
                    Text::new(resource_development_yield(resource, level).to_string()),
                    font.clone(),
                    layout,
                    line_height,
                    TextColor(normal_color),
                    Pickable::IGNORE,
                    UniversityYieldText,
                    ChildOf(view.details),
                ));
            }
        }
        let image = images
            .get_mut(view.details)
            .expect("bound University details picture");
        assets.replace_image(&image.image, picture.to_image(assets.default_dib_palette()));
    }
}
