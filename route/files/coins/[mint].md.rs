petal::route_file!(spec:petal::http_read_spec(5000),read:|c:&petal::Ctx|match petal::param(c,"mint"){Ok(m)=>crate::view::coin_page(m,crate::view::Format::Markdown),Err(e)=>e});
