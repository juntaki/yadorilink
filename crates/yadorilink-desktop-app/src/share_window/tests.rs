#![cfg(test)]

use super::*;

/// A window's state without a window. Nothing here needs an
/// `egui::Context`: the wake callback a real window supplies is the only
/// thing `EventSink` wants, and none of the paths exercised below paints
/// anything. The folder starts out `Linked` with a read already in
/// flight, so `refresh_access` records the refresh it was asked for
/// instead of starting a network call -- which is exactly the assertion
/// these tests want and the one thing they must not really do.
fn test_app() -> ShareApp {
    let (tx, rx) = mpsc::channel();
    let mut app = ShareApp::new("/folder".to_string(), rx, EventSink::new(tx, Arc::new(|| {})));
    app.folder = Folder::Linked { group_id: "group-1".to_string() };
    app.access_in_flight = true;
    app
}

fn deny_action() -> Action {
    // A waiting request has no device name, so its id IS its label --
    // see `render_pending_rows`.
    Action::Deny { device_id: "device-a".to_string(), device_label: "device-a".to_string() }
}

fn plain_outcome() -> ReplicaMembershipCommandOutcome {
    ReplicaMembershipCommandOutcome {
        handoffs: Vec::new(),
        forced_group_ids: Vec::new(),
        unknown_scope_operation_id: String::new(),
    }
}

/// A request that was genuinely still waiting is reported the way the
/// button described itself.
#[test]
fn a_denial_that_was_carried_out_is_reported_as_turned_down() {
    let mut app = test_app();
    app.apply_action_result(deny_action(), Ok(ActionOutcome::Denied(Box::new(plain_outcome()))));

    let notice = app.notice.as_ref().expect("a completed denial reports something");
    assert!(notice.ok);
    assert_eq!(notice.lines, vec![deny_done_line("device-a")]);
    assert!(notice.warnings.is_empty(), "an ordinary denial warns about nothing");
    assert!(app.access_refresh_queued, "the listing this changed must be re-read");
}

/// The bug this fix closes: a Deny clicked on a row that had already been
/// approved elsewhere used to revoke that live member and report it as a
/// request being turned down. It is no longer sent at all, and what the
/// person is told says so -- never "was turned down", which is the exact
/// claim that made a real removal read as a harmless refusal.
#[test]
fn a_denial_the_state_check_stopped_never_reports_a_request_as_turned_down() {
    for refusal in [DenyRefusal::AlreadyAdmitted, DenyRefusal::NoLongerListed] {
        let mut app = test_app();
        app.apply_action_result(deny_action(), Ok(ActionOutcome::DenyNotCarriedOut(refusal)));

        let notice = app.notice.as_ref().expect("a stopped denial reports something");
        assert!(!notice.ok, "nothing happened, so this must not read as a success");
        assert_eq!(notice.lines, vec![deny_not_carried_out_line("device-a", refusal)]);
        let line = &notice.lines[0];
        assert!(!line.contains("was turned down"), "{line}");
        assert!(app.access_refresh_queued, "a panel this stale must be re-read");
    }
}

/// The already-approved case points at the removal that WOULD do what the
/// person was reaching for, and says plainly that it is a different,
/// destructive action.
#[test]
fn a_denial_stopped_by_a_live_membership_points_at_the_removal_control() {
    let mut app = test_app();
    app.apply_action_result(
        deny_action(),
        Ok(ActionOutcome::DenyNotCarriedOut(DenyRefusal::AlreadyAdmitted)),
    );

    let line = &app.notice.as_ref().unwrap().lines[0];
    assert!(line.contains("now has access to this folder"), "{line}");
    assert!(line.contains(REMOVE_ACCESS_BUTTON), "{line}");
}

/// A denial runs the same mutation a removal runs, so it must show the
/// same daemon-computed warnings a removal shows. This outcome cannot
/// arise from an unforced denial in practice; the point is that the
/// outcome reaches the warning renderer at all, rather than being
/// discarded on the way -- discarding it is what let a real removal be
/// announced as a plain success.
#[test]
fn a_denials_daemon_outcome_is_shown_rather_than_discarded() {
    let mut app = test_app();
    let outcome = ReplicaMembershipCommandOutcome {
        forced_group_ids: vec!["group-1".to_string()],
        ..plain_outcome()
    };
    app.apply_action_result(deny_action(), Ok(ActionOutcome::Denied(Box::new(outcome))));

    let notice = app.notice.as_ref().unwrap();
    assert_eq!(
        notice.warnings,
        yadorilink_client_core::wording::membership_outcome_warnings(
            "revoke",
            &ReplicaMembershipCommandOutcome {
                forced_group_ids: vec!["group-1".to_string()],
                ..plain_outcome()
            },
        ),
    );
    assert!(!notice.warnings.is_empty());
}

fn test_modules() -> QrModules {
    // A 2x2 grid with one dark module at (1, 0), so the tests below can
    // check both the quiet-zone offset and the module scaling without
    // depending on any particular real QR payload's layout.
    QrModules { width: 2, dark: vec![false, true, false, false] }
}

#[test]
fn qr_image_is_square_and_includes_the_quiet_zone_on_every_side() {
    let image = qr_color_image(&test_modules(), 3);
    let expected = (2 + 2 * QR_QUIET_ZONE_MODULES) * 3;
    assert_eq!(image.size, [expected, expected]);
}

#[test]
fn qr_image_paints_each_dark_module_as_a_full_square_at_its_offset() {
    let module_px = 3;
    let image = qr_color_image(&test_modules(), module_px);
    let origin_x = (1 + QR_QUIET_ZONE_MODULES) * module_px;
    let origin_y = QR_QUIET_ZONE_MODULES * module_px;
    for dy in 0..module_px {
        for dx in 0..module_px {
            assert_eq!(
                image[(origin_x + dx, origin_y + dy)],
                egui::Color32::BLACK,
                "module pixel ({dx}, {dy}) should be dark"
            );
        }
    }
    // The neighbouring module is light, so the square does not bleed.
    assert_eq!(image[(origin_x - 1, origin_y)], egui::Color32::WHITE);
    assert_eq!(image[(origin_x + module_px, origin_y)], egui::Color32::WHITE);
}

/// The quiet zone is white all the way round -- a scanner needs it to
/// find the symbol's edge.
#[test]
fn qr_image_quiet_zone_is_light() {
    let image = qr_color_image(&test_modules(), 3);
    let [width, height] = image.size;
    for x in 0..width {
        assert_eq!(image[(x, 0)], egui::Color32::WHITE);
        assert_eq!(image[(x, height - 1)], egui::Color32::WHITE);
    }
    for y in 0..height {
        assert_eq!(image[(0, y)], egui::Color32::WHITE);
        assert_eq!(image[(width - 1, y)], egui::Color32::WHITE);
    }
}

/// A real invite payload encodes and paints without panicking, at the
/// module size this window actually uses.
#[test]
fn a_real_invite_url_renders_to_a_qr_image() {
    let url = yadorilink_client_core::wording::invite_url("0123456789abcdef");
    let modules = qr_modules(&url).expect("a short invite URL always encodes");
    let image = qr_color_image(&modules, QR_MODULE_PIXELS);
    let expected = (modules.width + 2 * QR_QUIET_ZONE_MODULES) * QR_MODULE_PIXELS;
    assert_eq!(image.size, [expected, expected]);
    assert!(image.pixels.contains(&egui::Color32::BLACK));
}
