use crate::gui::ColourSecurityValue;
use gtk::prelude::*;
use gtk::{
    glib::clone, ApplicationWindow, Box, Button, Dialog, DialogFlags, EventControllerKey, Grid,
    Label, Orientation, PasswordEntry, ResponseType,
};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;

use crate::gui::AttendanceData;

lazy_static! {
    static ref KEY_DATA: Mutex<String> = Mutex::new(String::new());
    static ref SECURITY_PIN: Mutex<u32> = Mutex::new(0);
}

pub fn show_pin_security(dialog_clone: Rc<Dialog>, colour_security: ColourSecurityValue) {
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

    dialog_clone.connect_response(|_, response_type| {
        if let ResponseType::Apply = response_type {
            println!("Beginning sign-in procedure!");
            // TODO sign-in code goes here, using
            // KEY_DATA, SECURITY_PIN, and colour_security
        }
    });

    dialog_clone.set_child(Some(&display_box));
    dialog_clone.add_buttons(&[("Sign In", ResponseType::Apply)]);
    dialog_clone.show();
}

pub fn scan(window: ApplicationWindow) -> Box {
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
                red.connect_clicked(move |btn| {
                    show_pin_security(
                        Rc::clone(&colour_security_dialog_red),
                        ColourSecurityValue::Red,
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
