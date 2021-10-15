use gtk::prelude::*;
use gtk::{Box, Label};

pub fn scan() -> Box {
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

    list_box
}
