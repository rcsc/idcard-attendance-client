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
    Label, ListBox, Orientation, PasswordEntry, ResponseType, Widget,
};
use reqwest::{blocking::Client, header::HeaderMap};
use std::cell::RefCell;
use std::collections::HashMap;
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

pub fn show_attendance_complete(
    dialog: Rc<Dialog>,
    user_full_name: String,
    dialog_buttons: Rc<RefCell<Vec<Widget>>>,
) {
    println!("Sign in successful.");
    let sign_in_label = Label::new(Some(&format!("Welcome, {}!", user_full_name)));

    dialog.connect_response(move |dialog_clone, response_type| {
        if let ResponseType::Close = response_type {
            dialog_clone.destroy();
        }
    });

    // Clear the dialog buttons so we only have a "close" button on the Dialog
    for dialog_button in dialog_buttons.borrow_mut().iter() {
        dialog_button
            .clone()
            .downcast::<gtk::Button>()
            .unwrap()
            .hide();
    }

    dialog.set_title(Some("Sign In"));
    dialog.set_child(Some(&sign_in_label));
    dialog.add_buttons(&[("Close", ResponseType::Close)]);
    dialog.show();
}

pub fn create_user_dialog(dialog: &Dialog, dialog_buttons: Rc<RefCell<Vec<Widget>>>) {
    unimplemented!()
}

pub fn choose_user_from_users_dialog(
    dialog: Rc<Dialog>,
    mut graphql_client: Client,
    hashed_data: String,
    log_attendance_variables: graphql::log_attendance::Variables,
    dialog_buttons: Rc<RefCell<Vec<Widget>>>,
) {
    let users_listbox = ListBox::new();
    let graphql_endpoint = get_config().attendance_rs_graphql_endpoint + "/graphql";
    // Get the list of users

    let request_body = graphql::ListUsers::build_query(graphql::list_users::Variables);
    let response = graphql_client
        .post(&graphql_endpoint)
        .json(&request_body)
        .send()
        .expect("Failed to send GraphQL request for users!");
    let mut user_uuid_list = vec![];
    if response.status().is_success() {
        let response_body: Response<graphql::list_users::ResponseData> = response
            .json()
            .expect("Failed to parse GraphQL response for users");
        println!("err {:?}", response_body.errors);
        if let None = response_body.errors {
            for user in response_body.data.unwrap().users {
                println!("{:?}", user.full_name);
                println!("{:?}", user.uuid);
                users_listbox.append(&Label::new(Some(&format!("{}", user.full_name))));
                user_uuid_list.push(user.uuid);
            }
        }
    }
    let dialog_clone = dialog.clone();
    users_listbox.connect_row_selected(move |listbox, row| {
        if let Some(row) = row {
            println!("row selected {}", user_uuid_list[row.index() as usize]);
            // Link them

            let request_body =
                graphql::UpdateUserAltID::build_query(graphql::update_user_alt_id::Variables {
                    uuid: Some(user_uuid_list[row.index() as usize].clone()),
                    alt_id_value: Some(hashed_data.clone()),
                });
            let response = graphql_client
                .post(&graphql_endpoint)
                .json(&request_body)
                .send()
                .expect("Failed to send GraphQL request for users!");
            if response.status().is_success() {
                let response_body: Response<graphql::update_user_alt_id::ResponseData> = response
                    .json()
                    .expect("Failed to parse GraphQL response for users");
                println!("err {:?}", response_body.errors);
                if let None = response_body.errors {
                    // resend logAttendance
                    let response = graphql_client
                        .post(&graphql_endpoint)
                        .json(&graphql::LogAttendance::build_query(
                            graphql::log_attendance::Variables {
                                alt_id_field: log_attendance_variables.alt_id_field.clone(),
                                alt_id_value: log_attendance_variables.alt_id_value.clone(),
                            },
                        ))
                        .send()
                        .expect("Failed to send GraphQL request to logAttendance!");

                    if response.status().is_success() {
                        let response_body: Response<graphql::log_attendance::ResponseData> =
                            response.json().expect("Failed to parse GraphQL response");
                        println!("err {:?}", response_body.errors);
                        if let None = response_body.errors {
                            // It worked
                            show_attendance_complete(
                                dialog_clone.clone(),
                                row.child()
                                    .unwrap()
                                    .downcast::<gtk::Label>()
                                    .unwrap()
                                    .text()
                                    .to_string(),
                                dialog_buttons.clone(),
                            )
                        }
                    }
                }
            }
        }
    });

    dialog.set_title(Some("Select User"));
    dialog.set_child(Some(&users_listbox));
}

pub fn show_pin_security(
    dialog_clone: Rc<Dialog>,
    colour_security: ColourSecurityValue,
    unlocked_keys: Rc<KeyData>,
    mut dialog_buttons: Rc<RefCell<Vec<Widget>>>,
    ctx: Rc<RefCell<Context>>,
) {
    println!(
        "Showing PIN security, colour_security was chosen as {:?}",
        colour_security
    );
    dialog_buttons
        .borrow_mut()
        .push(dialog_clone.add_button("Sign In", ResponseType::Apply));
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

    let dialog_clone_clone = dialog_clone.clone();

    dialog_clone.connect_response(move |dialog_clone_cloned, response_type| {
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

            // Clear these two values from RAM immediately
            *KEY_DATA.lock().unwrap() = "".to_string();
            *SECURITY_PIN.lock().unwrap() = 0;

            // TODO please don't print this unless logging has debugging enabled
            println!("hashed_data is {}", hashed_data);

            // GraphQL query code goes here
            // From https://github.com/graphql-rust/graphql-client/blob/main/examples/hasura/examples/hasura.rs
            let log_attendance_variables = graphql::log_attendance::Variables {
                alt_id_field: Some("idac_secbarcode_value".to_owned()),
                alt_id_value: Some(hashed_data.clone()),
            };

            let mut headers = HeaderMap::new();
            headers.insert(
                "Token",
                get_config()
                    .attendance_rs_token
                    .parse()
                    .expect("Failed to convert token to HeaderValue"),
            );
            let reqwest_client = Client::builder()
                .default_headers(headers)
                .build()
                .expect("Failed to create GraphQL request client");
            let request_body = graphql::LogAttendance::build_query(graphql::log_attendance::Variables {
                alt_id_field: log_attendance_variables.alt_id_field.clone(),
                alt_id_value: log_attendance_variables.alt_id_value.clone()
            });
            let graphql_endpoint = get_config().attendance_rs_graphql_endpoint + "/graphql";

            // TODO the slash in /graphql might not work if the "graphql_endpoint" variable ends with a slash.
            // Do something about this.
            let response = reqwest_client
                .post(&graphql_endpoint)
                .json(&request_body)
                .send()
                .expect("Failed to send GraphQL request to logAttendance!");

            if response.status().is_success() {
                let response_body: Response<graphql::log_attendance::ResponseData> =
                    response.json().expect("Failed to parse GraphQL response");
                println!("response_body.errors #{:?}", response_body.errors);
                // If it's a failure, we'll show the prompt to have the user choose their
                // account or create a new one.
                if let None = response_body.errors {
                    // Success!
                    let user_uuid = response_body.data.unwrap().log_attendance.user_uuid;
                    println!("response_body.data #{:?}", user_uuid);

                    // Query the user's uuid to find their name and provide a friendly message
                    let user_by_uuid =
                        graphql::UserByUuid::build_query(graphql::user_by_uuid::Variables {
                            uuid: Some(user_uuid),
                        });

                    let user_data_response = reqwest_client
                        .post(&graphql_endpoint)
                        .json(&user_by_uuid)
                        .send()
                        .expect("Failed to send GraphQL request to find user data!");

                    if user_data_response.status().is_success() {
                        let user_data_json: Response<graphql::user_by_uuid::ResponseData> =
                            user_data_response
                                .json()
                                .expect("Failed to parse GraphQL response as JSON");

                        println!("user data json errors #{:?}", user_data_json.errors);

                        let user_full_name = user_data_json
                            .data
                            .unwrap()
                            .user_by_uuid
                            .expect("Expected a user to be returned")
                            .full_name;

                        show_attendance_complete(
                            dialog_clone_clone.clone(),
                            user_full_name,
                            dialog_buttons.clone(),
                        );
                    }
                } else if let Some(errors) = response_body.errors {
                    // should be the first error if the user isn't found
                    if let Some(error) = errors.get(0) {
                        if error.message == "no rows returned by a query that expected to return at least one row" {
                            println!("NOTE no users found!");
                            choose_user_from_users_dialog(dialog_clone_clone.clone(), reqwest_client, hashed_data, log_attendance_variables, dialog_buttons.clone())
                        }
                    }
                }
            }
        }
    });

    dialog_clone.set_child(Some(&display_box));
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
                    &[],
                ));
                let dialog_buttons = Rc::new(RefCell::new(vec![]));
                dialog_buttons
                    .borrow_mut()
                    .push(colour_security_dialog.add_button("Cancel", ResponseType::Cancel));

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

                let dialog_buttons_red = Rc::clone(&dialog_buttons);
                let dialog_buttons_green = Rc::clone(&dialog_buttons);
                let dialog_buttons_blue = Rc::clone(&dialog_buttons);
                let dialog_buttons_orange = Rc::clone(&dialog_buttons);

                red.connect_clicked(move |btn| {
                    show_pin_security(
                        Rc::clone(&colour_security_dialog_red),
                        ColourSecurityValue::Red,
                        unlocked_keys_red.clone(),
                        dialog_buttons_red.clone(),
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
                        dialog_buttons_green.clone(),
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
                        dialog_buttons_orange.clone(),
                        ctx_orange.clone(),
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
                        dialog_buttons_blue.clone(),
                        ctx_blue.clone(),
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
