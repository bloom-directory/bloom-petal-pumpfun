petal::route_file!(
    spec: petal::static_read_spec().caps(&["bloom:http", "bloom:store", "bloom:vfs.read"]),
    read: |c: &petal::Ctx| {
        let w = match crate::wallet(c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        crate::view::holdings(c, w, crate::view::Format::Markdown)
    }
);
