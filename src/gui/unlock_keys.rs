use gtk::prelude::*;
use gtk::{Box, Button, Label, PasswordEntry};

use tss_esapi::Context;

use std::cell::RefCell;
use std::rc::Rc;

use crate::{
    gui::{AttendanceData, KeyData},
    keygen::{get_unlocked_key, APP_DATA},
};

lazy_static! {
    static ref KEY_DATA: KeyData = KeyData::default();
    static ref ATTENDANCE_DATA: AttendanceData = AttendanceData::default();
}

pub fn unlock_keys_widget(
    context: Rc<RefCell<Context>>,
    key_data: Rc<RefCell<KeyData>>,
    attendance_data: Rc<RefCell<AttendanceData>>,
) -> Box {
    let list_box = Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .margin_top(20)
        .margin_start(20)
        .margin_end(20)
        .build();

    let unlock_keys_title = Label::builder()
        .label("<b><big>Unlock Keys</big></b>")
        .use_markup(true)
        .build();

    let hmac_key_password = PasswordEntry::builder()
        .placeholder_text("HMAC Key Password")
        .build();
    let aes_key_password = PasswordEntry::builder()
        .placeholder_text("AES Key Password")
        .build();

    let unlock_button = Button::builder().label("Unlock Keys").build();

    list_box.append(&unlock_keys_title);
    list_box.append(&hmac_key_password);
    list_box.append(&aes_key_password);
    list_box.append(&unlock_button);

    unlock_button.connect_clicked(move |_| {
        (*key_data.borrow_mut()).aes_key_handle = Some(get_unlocked_key(
            &mut *context.borrow_mut(),
            hmac_key_password.text().to_string(),
            APP_DATA.data_dir().join("keys").join("aes.key"),
        ));
        (*key_data.borrow_mut()).hmac_key_handle = Some(get_unlocked_key(
            &mut *context.borrow_mut(),
            hmac_key_password.text().to_string(),
            APP_DATA.data_dir().join("keys").join("hmac.key"),
        ));

        println!("Unlocked the keys: {:#?}", key_data);
    });

    list_box
}
