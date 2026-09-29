petal::route_file!(spec:petal::http_read_spec(15_000),read:|c:&petal::Ctx|match petal::param(c,"mint"){Ok(m)=>crate::insight::trades(m),Err(e)=>e});
