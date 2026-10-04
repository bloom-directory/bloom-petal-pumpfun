petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:http", "bloom:store"]),
    read: |_: &petal::Ctx| petal::read_json_value(&crate::json!({"description":"write {} to check every unsettled limit order. Simulations are unsigned; eligible orders and pending cancellations resend identical signed bytes. Nothing is signed here. Run it from an agent or a timer; orders are not watched automatically. Confirmed fills and cancellations keep their slot until finality. An order that can no longer fill still reserves its slot until cancelled or its nonce changes."})),
    write: |c: &petal::Ctx, b: &[u8]| {
        if b.len() > 256 || !matches!(serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(b), Ok(ref object) if object.is_empty()) {
            return petal::error(-3, "write an empty JSON object {} to check_orders.json");
        }
        let w = match crate::wallet(c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        crate::orders::check(c, w)
    }
);
