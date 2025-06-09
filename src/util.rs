use::server_conf::abs_path_with_default;

pub fn abs_path(path: &str) -> String {
    abs_path_with_default(path, "/auth")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_abs_dir_with_default_prefix() {
        assert_eq!(abs_path("dir"), "/auth/dir");
        assert_eq!(abs_path("/dir"), "/auth/dir");
        assert_eq!(abs_path("/"), "/auth/");
        assert_eq!(abs_path(""), "/auth/");
    }
}
