use gtk::prelude::*;
use gtk::{ApplicationWindow, Box, EventControllerKey, Label};
use std::time::Duration;

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
    key_controller.connect_key_pressed(|event_controller_key, key, key_num, mod_type| {
        println!("pressed {:?} --- {:?}", key.to_unicode(), key.name());
        gtk::Inhibit(false)
    });

    // For some reason, this basically has to be added to the window.
    // This key controller will be used to read the barcode scanner (acting as a USB HID, but maybe
    // we will do the serial stuff at a later point)'s keyboard output.
    window.add_controller(&key_controller);

    list_box
}
