petal::route_file!(spec:petal::store_read_spec().caps(&["bloom:http","bloom:store"]),read:|c:&petal::Ctx|crate::route_operation(c));
