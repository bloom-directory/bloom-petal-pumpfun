petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:http", "bloom:store"]),
    read: |_: &petal::Ctx| petal::read_json_value(&crate::json!({"description":"write {} to check every open limit order: one whose price has reached its limit is sent, one sent is confirmed, and one that can never fill is retired. Nothing is signed here. Run it from an agent or a timer, as often as you like."})),
    write: |c: &petal::Ctx, _b: &[u8]| {
        let w = match crate::wallet(c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        crate::orders::check(c, w)
    }
);
