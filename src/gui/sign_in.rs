use gtk::prelude::*;
use gtk::{ApplicationWindow, Box, Dialog, DialogFlags, EventControllerKey, Label, ResponseType};
use std::sync::Mutex;
use std::time::Duration;

lazy_static! {
    static ref KEY_DATA: Mutex<String> = Mutex::new(String::new());
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
                println!("Beginning colour security!");
                let colour_security_dialog = Dialog::with_buttons::<ApplicationWindow>(
                    Some("hello there"),
                    Some(&window_clone),
                    DialogFlags::MODAL | DialogFlags::DESTROY_WITH_PARENT,
                    &[("cancel", ResponseType::Ok)],
                );
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
