// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use figment::{
    providers::{Data, Format, Json, Toml},
    Figment,
};
use tracing::info;

trait MaybeNested {
    fn maybe_nested(self, nested: bool) -> Self;
}

impl<T: Format> MaybeNested for Data<T> {
    fn maybe_nested(self, nested: bool) -> Self {
        if nested {
            self.nested()
        } else {
            self
        }
    }
}

fn load_config_file(path: &str, nested: bool, figment: Figment) -> Figment {
    if path.ends_with(".json") {
        return figment.merge(Json::file(path).maybe_nested(nested));
    }
    if path.ends_with(".toml") {
        return figment.merge(Toml::file(path).maybe_nested(nested));
    }
    figment.merge(Json::file(path).maybe_nested(nested))
}

fn load_config_in_dir(name: &str, path: &str, nested: bool, mut figment: Figment) -> Figment {
    for ext in ["toml", "json"] {
        let filename = format!("{}/{}.{}", path, name, ext);
        if std::path::Path::new(&filename).exists() {
            info!("Loading config file: {}", filename);
            figment = load_config_file(&filename, nested, figment);
        }
    }
    figment
}

fn search_load_config(
    name: &str,
    search_paths: &[&str],
    default_toml: &str,
    leaf_config: Option<&str>,
    nested: bool,
) -> Figment {
    let mut figment = Figment::from(rocket::Config::default())
        .merge(Toml::string(default_toml).maybe_nested(nested));
    for path in search_paths {
        figment = load_config_in_dir(name, path, nested, figment);
    }
    match leaf_config {
        Some(path) => load_config_file(path, nested, figment),
        None => figment,
    }
}

pub fn load_config(
    name: &str,
    default_toml: &str,
    leaf_config: Option<&str>,
    nested: bool,
) -> Figment {
    let etc_path = format!("/etc/{name}");
    search_load_config(name, &[&etc_path, "."], default_toml, leaf_config, nested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_files(dir: &TempDir) -> (String, String) {
        let json_path = dir.path().join("config.json");
        let toml_path = dir.path().join("config.toml");

        fs::write(&json_path, r#"{"test": "json_value"}"#).unwrap();
        fs::write(&toml_path, r#"test = "toml_value""#).unwrap();

        (
            json_path.to_str().unwrap().to_string(),
            toml_path.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn test_load_config_file_json() {
        let temp_dir = TempDir::new().unwrap();
        let (json_path, _) = setup_test_files(&temp_dir);

        let figment = Figment::new();
        let result = load_config_file(&json_path, false, figment);

        assert_eq!(
            result.extract_inner::<String>("test").unwrap(),
            "json_value"
        );
    }

    #[test]
    fn test_load_config_file_toml() {
        let temp_dir = TempDir::new().unwrap();
        let (_, toml_path) = setup_test_files(&temp_dir);

        let figment = Figment::new();
        let result = load_config_file(&toml_path, false, figment);

        assert_eq!(
            result.extract_inner::<String>("test").unwrap(),
            "toml_value"
        );
    }

    #[test]
    fn test_load_config_in_dir() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();

        fs::write(
            temp_dir.path().join("test.json"),
            r#"{"key": "json_value"}"#,
        )
        .unwrap();

        let figment = Figment::new();
        let result = load_config_in_dir("test", dir_path, false, figment);

        assert_eq!(result.extract_inner::<String>("key").unwrap(), "json_value");
    }

    #[test]
    fn test_search_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();

        fs::write(
            temp_dir.path().join("app.toml"),
            r#"override = "from_toml""#,
        )
        .unwrap();

        let default_toml = r#"
foo = "value"
override = "default"
"#;

        let result = search_load_config("app", &[dir_path], default_toml, None, false);

        assert_eq!(result.extract_inner::<String>("foo").unwrap(), "value");
        assert_eq!(
            result.extract_inner::<String>("override").unwrap(),
            "from_toml"
        );
    }

    #[test]
    fn test_search_load_config2() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();
        let dir1_path = temp_dir1.path().to_str().unwrap();
        let dir2_path = temp_dir2.path().to_str().unwrap();

        // Set up config in first directory
        fs::write(
            temp_dir1.path().join("app.toml"),
            r#"
base = "from_dir1"
override1 = "dir1_value"
common = "dir1_value"
"#,
        )
        .unwrap();

        // Set up config in second directory
        fs::write(
            temp_dir2.path().join("app.json"),
            r#"{
                "override1": "dir2_value",
                "override2": "dir2_value",
                "common": "dir2_value"
            }"#,
        )
        .unwrap();

        // Create leaf config file
        let leaf_config = temp_dir1.path().join("leaf.json");
        fs::write(
            &leaf_config,
            r#"{
                "override2": "leaf_value",
                "leaf_only": "leaf_value"
            }"#,
        )
        .unwrap();

        let default_toml = r#"
base = "default"
override1 = "default"
override2 = "default"
common = "default"
"#;

        let result = search_load_config(
            "app",
            &[dir1_path, dir2_path],
            default_toml,
            Some(leaf_config.to_str().unwrap()),
            false,
        );

        // Test layered configuration
        assert_eq!(result.extract_inner::<String>("base").unwrap(), "from_dir1");
        assert_eq!(
            result.extract_inner::<String>("override1").unwrap(),
            "dir2_value"
        );
        assert_eq!(
            result.extract_inner::<String>("override2").unwrap(),
            "leaf_value"
        );
        assert_eq!(
            result.extract_inner::<String>("common").unwrap(),
            "dir2_value"
        );
        assert_eq!(
            result.extract_inner::<String>("leaf_only").unwrap(),
            "leaf_value"
        );
    }

    #[test]
    fn test_load_config_file_json_nested() {
        let temp_dir = TempDir::new().unwrap();
        let (json_path, _) = setup_test_files(&temp_dir);

        // Write nested JSON configuration
        fs::write(&json_path, r#"{"config": {"test": "nested_json_value"}}"#).unwrap();

        let figment = Figment::new();
        let result = load_config_file(&json_path, true, figment).select("config");

        assert_eq!(
            result.extract_inner::<String>("test").unwrap(),
            "nested_json_value"
        );
    }

    #[test]
    fn test_load_config_file_toml_nested() {
        let temp_dir = TempDir::new().unwrap();
        let (_, toml_path) = setup_test_files(&temp_dir);

        // Write nested TOML configuration
        fs::write(
            &toml_path,
            r#"
[config]
test = "nested_toml_value"
"#,
        )
        .unwrap();

        let figment = Figment::new();
        let result = load_config_file(&toml_path, true, figment).select("config");

        assert_eq!(
            result.extract_inner::<String>("test").unwrap(),
            "nested_toml_value"
        );
    }

    #[test]
    fn test_search_load_config_nested() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();

        // Write nested configuration
        fs::write(
            temp_dir.path().join("app.toml"),
            r#"
[config]
override = "nested_from_toml"
"#,
        )
        .unwrap();

        let default_toml = r#"
[config]
foo = "nested_value"
override = "default"
"#;

        let result =
            search_load_config("app", &[dir_path], default_toml, None, true).select("config");

        assert_eq!(
            result.extract_inner::<String>("foo").unwrap(),
            "nested_value"
        );
        assert_eq!(
            result.extract_inner::<String>("override").unwrap(),
            "nested_from_toml"
        );
    }
}
