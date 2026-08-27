use super::*;
use crate::RetailFonts;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

const UNIVERSITY_KINDS: [CivilianUnitKind; 7] = [
    CivilianUnitKind::Miner,
    CivilianUnitKind::Prospector,
    CivilianUnitKind::Farmer,
    CivilianUnitKind::Forester,
    CivilianUnitKind::Engineer,
    CivilianUnitKind::Rancher,
    CivilianUnitKind::Driller,
];

pub(in crate::ui::city) struct UniversityUi {
    pub(in crate::ui::city) selected: CivilianUnitKind,
    rows: [(CivilianUnitKind, SelectionRow); 7],
    unit: Entity,
    description: Entity,
    costs: [Entity; 3],
    available: [Entity; 3],
    tier_labels: [Entity; 3],
    details: Entity,
}

pub(in crate::ui::city) fn bind_university(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) -> UniversityUi {
    let nation = MajorNationId::from_nation(state.turn().active_nation).expect("major nation");
    let available = state.technology().city_capabilities_by_nation[nation]
        .university
        .available;
    let rows = std::array::from_fn(|index| {
        let kind = UNIVERSITY_KINDS[index];
        let (order_tag, button_tag) = generated::UNIVERSITY_ROW_CONTROLS[index];
        let bound = bind_recruitment_order_row(
            commands,
            root,
            tree,
            CityOrderId::CivilianRecruit(kind),
            order_tag,
        );
        let button = tree.find(root, button_tag);
        let row_available = available[kind];
        bound.set_available(commands, row_available);
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert(if row_available {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
            if row_available {
                button_commands.remove::<InteractionDisabled>();
            } else {
                button_commands.insert(InteractionDisabled);
            }
        }
        bind_row_selection(commands, tree, root, bound.row, button, move |view| {
            if let CityDialogView::University(u) = view {
                u.selected = kind;
            }
        });
        commands.entity(bound.quantity).insert(InteractionDisabled);
        (kind, SelectionRow(button, bound.quantity))
    });
    let dlog = tree.find(root, fourcc!("DLOG"));
    let details_base = assets.indexed_picture(PictureId::new(9900));
    commands.entity(dlog).insert(ImageNode::new(
        assets.add_image(details_base.to_image(assets.default_dib_palette())),
    ));
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
    UniversityUi {
        selected: CivilianUnitKind::Miner,
        rows,
        unit,
        description,
        costs,
        available,
        tier_labels,
        details: dlog,
    }
}

pub(in crate::ui::city) fn render_university(
    view: &UniversityUi,
    session: &GameSession,
    assets: &mut RetailUiAssets,
    fonts: &RetailFonts,
    font_assets: &Assets<Font>,
    ui: &mut CityUi,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    let nation = session.active_major_nation();
    for &(kind, row) in &view.rows {
        sync_recruitment_row(
            ui,
            row,
            kind == view.selected,
            session
                .game
                .city_order_quantity(nation, CityOrderId::CivilianRecruit(kind))
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
    ui.text(
        view.unit,
        assets.string(kind.name_string()),
    );
    ui.text(
        view.description,
        assets.string(kind.description_string()),
    );
    let values = [
        1.to_string(),
        spec.primary.per_unit().to_string(),
        format_currency(i32::from(spec.cash_per_unit)),
        workforce_available.to_string(),
        city.stockpile[spec.primary.resource].to_string(),
        format_currency(major.common.treasury),
    ];
    for (entity, value) in view.costs.iter().chain(&view.available).zip(&values) {
        ui.text(*entity, value.clone());
    }
    let insufficiencies = [
        workforce_available < 1,
        city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
        major.common.treasury < i32::from(spec.cash_per_unit),
    ];
    for (entity, insufficient) in view.available.iter().zip(&insufficiencies) {
        ui.color(
            *entity,
            if *insufficient {
                warning_color
            } else {
                normal_color
            },
        );
    }
    for (entity, index) in view.tier_labels.iter().zip(0..3) {
        ui.visible(*entity, (index as u8) < maximum.retail());
    }
    let mut picture = assets.indexed_picture(PictureId::new(9900));
    let preview = assets.indexed_picture(kind.university_preview_picture());
    picture.blit_keyed_at(&preview, IVec2::new(0x7c, 0x5c), 0x10);
    let icons = assets.indexed_picture(PictureId::new(750));
    let mut text = RetailRasterTextPainter::from_preset(
        fonts,
        font_assets,
        RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        },
    )
    .expect("text style");
    let mut running_max = UniversityRequirementLevel::None;
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
            text.draw(
                &mut picture,
                IVec2::new(i32::from(level) * 40 + 39, row_index as i32 * 25 + 289),
                &resource_development_yield(resource, level).to_string(),
                0xd2,
            );
        }
    }
    let image = ui.images.get_mut(view.details).expect("details");
    assets.replace_image(&image.image, picture.to_image(assets.default_dib_palette()));
}
