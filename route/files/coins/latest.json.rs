petal::route_file!(
    spec: petal::http_read_spec(15_000),
    read: |_c: &petal::Ctx| crate::coins(crate::Listing::Latest)
);
