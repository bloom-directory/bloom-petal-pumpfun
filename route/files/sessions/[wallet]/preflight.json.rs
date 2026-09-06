petal::route_file!(
    spec: petal::static_read_spec(),
    read: |c: &petal::Ctx| {
        let w = match crate::wallet(c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        crate::preflight(c, w)
    }
);
