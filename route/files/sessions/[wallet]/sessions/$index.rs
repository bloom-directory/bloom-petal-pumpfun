petal::route_file!(spec:petal::store_dir_spec().caps(&["bloom:store"]),ctx_list:|c:&petal::Ctx|crate::list_sessions(c));
