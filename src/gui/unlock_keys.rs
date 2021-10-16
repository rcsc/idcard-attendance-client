use gtk::prelude::*;
use gtk::{Box, Button, Label, PasswordEntry};

use tss_esapi::Context;

use std::cell::RefCell;
use std::rc::Rc;

use crate::{
    gui::{AttendanceData, KeyData},
    keygen::{get_unlocked_key, APP_DATA},
};

pub fn unlock_keys_widget(context: Rc<RefCell<Context>>, key_data: Rc<RefCell<KeyData>>) -> Box {
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

    unlock_button.connect_clicked(move |button| {
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

        // Switch the child for the parent
        // TODO handle it when get_unlocked_key fails and display a visual response
        //
        // ...Wow this code is janky
        // If we try to just take the parent of list_box,
        // then we would get ownership issues since list_box is
        // moved into this closure when we use it.
        let window = button
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .downcast::<gtk::ApplicationWindow>()
            .unwrap();

        // Start signing in now that the key handles are opened
        // the keys are unlocked
        window.set_child(Some(&crate::gui::sign_in::scan(window.clone())));
    });

    list_box
}
