petal::route_file!(
    spec: petal::static_read_spec().caps(&["bloom:http", "bloom:store"]),
    read: |c: &petal::Ctx| {
        let w = match crate::wallet(c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        crate::preflight(c, w)
    }
);
