petal::route_file!(spec: petal::http_read_spec(15_000), read: |_c: &petal::Ctx| crate::view::listing(crate::Listing::Live, crate::view::Format::Html));
