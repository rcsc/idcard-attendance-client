#[macro_use]
extern crate lazy_static;

mod colour_security;
mod config;
mod graphql;
mod gui;
mod keygen;
mod tpm;

use gtk::prelude::*;
use gtk::{Application, ApplicationWindow, Button, EventControllerKey};
use std::cell::RefCell;
use std::rc::Rc;
use tss_esapi::{tcti_ldr::TabrmdConfig, Context};

fn main() {
    // Test reading back stuff
    let mut context = Rc::new(RefCell::new(
        Context::new_with_tabrmd(TabrmdConfig::default()).expect("Failed to open TPM!"),
    ));
    let key_data = Rc::new(RefCell::new(gui::KeyData::default()));

    // Set Password session
    // keygen::check_create_keys(&mut *context.borrow_mut());
    // keygen::create_colour_security_values(&mut *context.borrow_mut());

    let app = Application::builder()
        .application_id("club.ridgecompsci.idcard-attendance-client")
        .build();

    app.connect_activate(move |app: &Application| {
        // Inspired by the gtk4-rs css example
        let css_provider = gtk::CssProvider::new();
        let style = include_bytes!("gui/styles.css");

        css_provider.load_from_data(style);
        gtk::StyleContext::add_provider_for_display(
            &gdk::Display::default().expect("Failed to make a GDK display"),
            &css_provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );

        let window = ApplicationWindow::builder()
            .application(app)
            .title("Attendance")
            .build();

        window.set_child(Some(&gui::unlock_keys::unlock_keys_widget(context.clone())));

        window.present();
    });

    app.run();

    // context.execute_with_sessions((Some(AuthSession::Password), None, None), |context| {
    //     crate::tpm::evict_key(context, ObjectHandle::None, 0x81050001)
    //         .expect("Failed to evict the created primary key!");

    //     let primary_key = crate::tpm::create_write_key(
    //         context,
    //         PathBuf::from("test_primary.key"),
    //         crate::tpm::KeyType::Primary,
    //         tpm::PersistType::Persist(u32::from_be_bytes([0x81, 0x05, 0x00, 0x01])),
    //         tpm::KeyAuthType::Password("test-password".to_string()),
    //     )
    //     .expect("Failed to create a primary key!");

    //     let read_primary_key =
    //         crate::tpm::load_key_from_file(context, PathBuf::from("test_primary.key"))
    //             .expect("Failed to read primary key.");

    //     context
    //         .tr_set_auth(
    //             read_primary_key.into(),
    //             &Auth::try_from("test-password".as_bytes())
    //                 .expect("failed to create authentication for parent key"),
    //         )
    //         .expect("Failed to authenticate parent key");

    //     let hmac_key = crate::tpm::create_write_key(
    //         context,
    //         PathBuf::from("test_hmac.key"),
    //         crate::tpm::KeyType::HMAC {
    //             parent_key: read_primary_key.into(),
    //         },
    //         tpm::PersistType::Persist(u32::from_be_bytes([0x81, 0x06, 0x00, 0x01])),
    //         tpm::KeyAuthType::Password("test-password".to_string()),
    //     )
    //     .expect("Failed to create a primary key!");
    // });
}
