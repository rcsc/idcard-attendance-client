use crate::{
    config::get_config,
    graphql,
    gui::{ColourSecurityValue, KeyData},
    keygen::APP_DATA,
    tpm,
};
use argon2::{Argon2, PasswordHasher};
use graphql_client::Response;
use graphql_client::{reqwest::post_graphql_blocking, GraphQLQuery};
use gtk::prelude::*;
use gtk::{
    glib::clone, ApplicationWindow, Box, Button, Dialog, DialogFlags, EventControllerKey, Grid,
    Label, Orientation, PasswordEntry, ResponseType,
};
use reqwest::{blocking::Client, header::HeaderMap};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;
use tss_esapi::Context;

use crate::gui::AttendanceData;

lazy_static! {
    static ref KEY_DATA: Mutex<String> = Mutex::new(String::new());
    static ref SECURITY_PIN: Mutex<u32> = Mutex::new(0);
}

// TODO generate a new random string at compile time if we're building in release mode?
static CONSTANT_SALT: &'static str = "LUAboRsoLUiNJVc5HVBX";

pub fn show_pin_security(
    dialog_clone: Rc<Dialog>,
    colour_security: ColourSecurityValue,
    unlocked_keys: Rc<KeyData>,
    ctx: Rc<RefCell<Context>>,
) {
    println!(
        "Showing PIN security, colour_security was chosen as {:?}",
        colour_security
    );
    let display_box = Box::new(Orientation::Vertical, 10);
    let number_grid = Grid::new();
    let pin_preview = Rc::new(
        PasswordEntry::builder()
            .can_focus(false)
            .editable(false)
            .show_peek_icon(false)
            .build(),
    );

    display_box.append(&*Rc::clone(&pin_preview));
    display_box.append(&number_grid);

    for row in 0..4 {
        for column in 0..3 {
            let num = (row * 3) + column + 1;
            let number_button = if num > 9 {
                // number 11 is actually zero, since if you think about a PIN pad this is how it
                // works
                if num == 11 {
                    Button::with_label("0")
                } else {
                    continue;
                }
            } else {
                Button::with_label(&format!("{}", num))
            };

            let pin_preview_closure = Rc::clone(&pin_preview);
            number_button.connect_clicked(move |btn| {
                // Unwrapping the
                let mut locked_security_pin = SECURITY_PIN.lock().unwrap();
                *locked_security_pin *= 10;
                *locked_security_pin += {
                    // If any of the unwraps here fail, then something is wrong.
                    // We dynamically hard-code the values of the labels to be parseable,
                    // as they are integers.
                    let option_label_value = btn.label().unwrap();
                    option_label_value.as_str().parse::<u32>().unwrap()
                };
                pin_preview_closure.set_text(&format!("{}", *locked_security_pin));
                println!("{}", *locked_security_pin);
            });
            // row + 1 since we are attaching the pin_preview in the first row and
            // want it to be clear
            number_grid.attach(&number_button, column, row, 1, 1);
        }
    }

    dialog_clone.connect_response(move |_, response_type| {
        if let ResponseType::Apply = response_type {
            println!("Beginning sign-in procedure!");
            // TODO sign-in code goes here, using
            // KEY_DATA, SECURITY_PIN, and colour_security

            // Step 1: AES decrypt the security PIN
            // Copied from keygen. TODO maybe we can get this to work a different way so it's less painful?
            let colour_security_dir = APP_DATA.data_dir().join("colour_security");
            let encryption_data = bincode::deserialize(
                &std::fs::read(colour_security_dir.join(match colour_security {
                    ColourSecurityValue::Blue => "blue",
                    ColourSecurityValue::Green => "green",
                    ColourSecurityValue::Orange => "orange",
                    ColourSecurityValue::Red => "red",
                }))
                .unwrap(),
            )
            .expect("Failed to load encrypted colour security keys for decryption");
            let decrypted_colour_security_data = String::from_utf8(
                (*ctx.borrow_mut())
                    .execute_with_nullauth_session(|ctx| {
                        tpm::aes_decrypt(
                            ctx,
                            // We can unwrap since this SHOULD be Some
                            unlocked_keys.aes_key_handle.unwrap(),
                            &encryption_data,
                        )
                    })
                    .expect("Failed to decrypt colour_security data!"),
            )
            .expect("Failed to convert decrypted colour_security string into a String");

            // Run argon2 with this newfound data
            // We are NOT salting passwords.
            // This would be unnecessary and would not help prevent against attacks.
            let argon2 = Argon2::default();
            let hashed_data = argon2
                .hash_password(
                    (String::new()
                        + &(*KEY_DATA.lock().unwrap())
                        + &decrypted_colour_security_data
                        + &(*SECURITY_PIN.lock().unwrap()).to_string())
                        .as_bytes(),
                    CONSTANT_SALT,
                )
                .expect("Failed to hash the provided data")
                .to_string();
            println!("hashed_data is {}", hashed_data);

            // GraphQL query code goes here
            // From https://github.com/graphql-rust/graphql-client/blob/main/examples/hasura/examples/hasura.rs
            let log_attendance_variables = graphql::log_attendance::Variables {
                alt_id_field: Some("idac-secbarcode-value".to_owned()),
                alt_id_value: Some(hashed_data),
            };

            let reqwest_client = Client::new();
            let request_body = graphql::LogAttendance::build_query(log_attendance_variables);
            let mut headers = HeaderMap::new();
            headers.insert(
                "Token",
                get_config()
                    .attendance_rs_token
                    .parse()
                    .expect("Failed to convert token to HeaderValue"),
            );

            // TODO the slash in /graphql might not work if the "graphql_endpoint" variable ends with a slash.
            // Do something about this.
            let response = reqwest_client
                .post(get_config().attendance_rs_graphql_endpoint + "/graphql")
                .headers(headers)
                .json(&request_body)
                .send()
                .expect("Failed to send GraphQL request!");
            if response.status().is_success() {
                let response_body: Response<graphql::log_attendance::ResponseData> =
                    response.json().expect("Failed to parse GraphQL response");
                println!("response_body.errors #{:?}", response_body.errors);
                if let None = response_body.errors {
                    // Success!
                    println!(
                        "response_body.data #{:?}",
                        response_body.data.unwrap().log_attendance.user_uuid
                    )
                }
            }
        }
    });

    dialog_clone.set_child(Some(&display_box));
    dialog_clone.add_buttons(&[("Sign In", ResponseType::Apply)]);
    dialog_clone.show();
}

pub fn scan(
    context: Rc<RefCell<Context>>,
    window: ApplicationWindow,
    unlocked_keys: KeyData,
) -> Box {
    let list_box = Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .margin_top(20)
        .margin_start(20)
        .margin_end(20)
        .build();

    let unlock_keys_title = Label::builder()
        .label("<b><big>Sign In</big></b>")
        .use_markup(true)
        .build();

    list_box.append(&unlock_keys_title);

    let key_controller = EventControllerKey::new();
    let window_clone = window.clone();
    let unlocked_keys_rc = Rc::new(unlocked_keys);

    key_controller.connect_key_pressed(move |event_controller_key, key, key_num, mod_type| {
        println!("pressed {:?} --- {:?}", key.to_unicode(), key.name());
        if let Some(unicode_value) = key.to_unicode() {
            if unicode_value == '\r' {
                // Begin colour security
                // TODO clear the KEY_DATA variable and move it to a separate string so we can pass
                // it into show_pin_security
                println!("Beginning colour security!");
                let colour_security_dialog = Rc::new(Dialog::with_buttons::<ApplicationWindow>(
                    Some("Colour Security"),
                    Some(&window_clone),
                    DialogFlags::MODAL
                        | DialogFlags::DESTROY_WITH_PARENT
                        | DialogFlags::USE_HEADER_BAR,
                    &[("Cancel", ResponseType::Cancel)],
                ));

                let dialog_buttons_grid = Grid::new();

                let colour_security_dialog_red = Rc::clone(&colour_security_dialog);
                let colour_security_dialog_green = Rc::clone(&colour_security_dialog);
                let colour_security_dialog_blue = Rc::clone(&colour_security_dialog);
                let colour_security_dialog_orange = Rc::clone(&colour_security_dialog);

                let red = Button::builder()
                    .label("Red")
                    .css_classes(vec!["red".to_string()])
                    .build();

                let unlocked_keys_red = Rc::clone(&unlocked_keys_rc);
                let unlocked_keys_green = Rc::clone(&unlocked_keys_rc);
                let unlocked_keys_blue = Rc::clone(&unlocked_keys_rc);
                let unlocked_keys_orange = Rc::clone(&unlocked_keys_rc);

                let ctx_red = Rc::clone(&context);
                let ctx_green = Rc::clone(&context);
                let ctx_blue = Rc::clone(&context);
                let ctx_orange = Rc::clone(&context);

                red.connect_clicked(move |btn| {
                    show_pin_security(
                        Rc::clone(&colour_security_dialog_red),
                        ColourSecurityValue::Red,
                        unlocked_keys_red.clone(),
                        ctx_red.clone(),
                    )
                });

                let green = Button::builder()
                    .label("Green")
                    .css_classes(vec!["green".to_string()])
                    .build();
                green.connect_clicked(move |btn| {
                    show_pin_security(
                        Rc::clone(&colour_security_dialog_green),
                        ColourSecurityValue::Green,
                        unlocked_keys_green.clone(),
                        ctx_green.clone(),
                    )
                });

                let orange = Button::builder()
                    .label("Orange")
                    .css_classes(vec!["orange".to_string()])
                    .build();
                orange.connect_clicked(move |btn| {
                    show_pin_security(
                        Rc::clone(&colour_security_dialog_orange),
                        ColourSecurityValue::Orange,
                        unlocked_keys_orange.clone(),
                        ctx_blue.clone(),
                    )
                });
                let blue = Button::builder()
                    .label("Blue")
                    .css_classes(vec!["blue".to_string()])
                    .build();
                blue.connect_clicked(move |btn| {
                    show_pin_security(
                        Rc::clone(&colour_security_dialog_blue),
                        ColourSecurityValue::Blue,
                        unlocked_keys_blue.clone(),
                        ctx_orange.clone(),
                    )
                });

                dialog_buttons_grid.attach(&red, 0, 0, 1, 1);
                dialog_buttons_grid.attach(&green, 1, 0, 1, 1);
                dialog_buttons_grid.attach(&blue, 0, 1, 1, 1);
                dialog_buttons_grid.attach(&orange, 1, 1, 1, 1);

                colour_security_dialog.set_child(Some(&dialog_buttons_grid));

                colour_security_dialog.set_transient_for(Some(&window_clone));
                colour_security_dialog.show()
            } else {
                KEY_DATA.lock().unwrap().push(unicode_value);
            }
            println!("key data is {:?}", KEY_DATA.lock().unwrap());
        }
        gtk::Inhibit(false)
    });
    // For some reason, this basically has to be added to the window.
    // This key controller will be used to read the barcode scanner (acting as a USB HID, but maybe
    // we will do the serial stuff at a later point)'s keyboard output.
    window.add_controller(&key_controller);

    list_box
}
