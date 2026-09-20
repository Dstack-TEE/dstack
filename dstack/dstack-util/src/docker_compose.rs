// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use bollard::container::{ListContainersOptions, RemoveContainerOptions};
use bollard::Docker;
use fs_err as fs;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// Holds parsed information from a docker-compose file
#[derive(Debug)]
pub struct ComposeInfo {
    pub project_name: String,
    pub service_names: std::collections::HashSet<String>,
}

/// Parse a docker-compose file and extract project name and service names
///
/// The caller deletes containers whose service is absent from `service_names`,
/// so a service this parser cannot see is a live container it destroys. That
/// makes an incomplete answer worse than no answer, and `include:` merges in
/// services from files that are not read here at all -- Compose starts them and
/// labels them with this same project. Refuse rather than guess.
pub fn parse_docker_compose_file(compose_file: impl AsRef<Path>) -> Result<ComposeInfo> {
    let compose_content =
        fs::read_to_string(compose_file.as_ref()).context("failed to read docker-compose file")?;

    let yaml_docs = YamlLoader::load_from_str(&compose_content).context("failed to parse YAML")?;
    let yaml_doc = yaml_docs.first().context("empty YAML document")?;

    if !yaml_doc["include"].is_badvalue() {
        bail!("'include' brings in services this parser cannot enumerate");
    }

    // Extract project name
    let project_name = if let Some(name) = yaml_doc["name"].as_str() {
        name.to_string()
    } else {
        get_project_name(compose_file.as_ref())?
    };

    // Extract service names
    let services = match &yaml_doc["services"] {
        Yaml::Hash(m) => m,
        _ => anyhow::bail!("missing or invalid 'services' field"),
    };

    let service_names = services
        .keys()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();

    Ok(ComposeInfo {
        project_name,
        service_names,
    })
}

/// A service image a Docker Hub mirror could substitute.
#[derive(Debug, PartialEq, Eq)]
pub struct UnpinnedImage {
    pub service: String,
    /// The image reference as written, or `build` for a service whose image is
    /// produced from a Dockerfile whose `FROM` this file cannot show.
    pub image: String,
}

/// Report the service images a Docker Hub mirror could substitute.
///
/// `registry-mirrors` in `daemon.json` only ever serves Docker Hub, and the
/// daemon rejects a manifest whose digest does not match a `@sha256:`
/// reference. So the substitutable images are exactly the Hub-resolving ones
/// written without a digest -- plus any service built locally, because the
/// `FROM` of its Dockerfile is pulled through the same mirror and is not in
/// this file at all.
///
/// Returns an error when the file cannot be enumerated, which the caller must
/// treat the same as "not pinned": an image this function cannot see is an
/// image it cannot vouch for.
pub fn unpinned_hub_images(compose_yaml: &str) -> Result<Vec<UnpinnedImage>> {
    let yaml_docs = YamlLoader::load_from_str(compose_yaml).context("failed to parse YAML")?;
    let yaml_doc = yaml_docs.first().context("empty YAML document")?;
    if !yaml_doc["include"].is_badvalue() {
        bail!("'include' pulls in services this parser cannot enumerate");
    }
    let Yaml::Hash(services) = &yaml_doc["services"] else {
        bail!("missing or invalid 'services' field");
    };

    let mut unpinned = vec![];
    for (name, service) in services {
        let service_name = name
            .as_str()
            .unwrap_or("<non-string service key>")
            .to_string();
        if !service["build"].is_badvalue() {
            unpinned.push(UnpinnedImage {
                service: service_name,
                image: "build".to_string(),
            });
            continue;
        }
        let image = &service["image"];
        if image.is_badvalue() {
            // No image and no build: compose itself rejects this later. Nothing
            // is pulled for it here, so it cannot be substituted.
            continue;
        }
        let Some(image) = image.as_str() else {
            bail!("service {service_name} has a non-string 'image'");
        };
        if !resolves_to_docker_hub(image) || image.contains('@') {
            continue;
        }
        unpinned.push(UnpinnedImage {
            service: service_name,
            image: image.to_string(),
        });
    }
    Ok(unpinned)
}

/// Whether an image reference resolves to Docker Hub, which is the only
/// registry `registry-mirrors` applies to.
///
/// Docker reads the part before the first `/` as a registry host only when it
/// contains a `.` or a `:`, or is exactly `localhost`; otherwise the whole
/// reference is a Hub repository (`nginx`, `library/nginx`, `myorg/app`).
fn resolves_to_docker_hub(image: &str) -> bool {
    const HUB_HOSTS: &[&str] = &[
        "docker.io",
        "index.docker.io",
        "registry-1.docker.io",
        "registry.hub.docker.com",
    ];
    let Some((head, _)) = image.split_once('/') else {
        return true;
    };
    if !head.contains('.') && !head.contains(':') && head != "localhost" {
        return true;
    }
    HUB_HOSTS.contains(&head)
}

fn get_project_name(compose_file: impl AsRef<Path>) -> Result<String> {
    let project_name = fs::canonicalize(compose_file)
        .context("failed to canonicalize compose file")?
        .parent()
        .context("failed to get parent directory of compose file")?
        .file_name()
        .context("failed to get file name of compose file")?
        .to_string_lossy()
        .into_owned();
    Ok(project_name)
}

/// Remove orphaned containers using Docker daemon API
pub async fn remove_orphans(compose_file: impl AsRef<Path>, dry_run: bool) -> Result<()> {
    // Connect to Docker daemon
    let docker =
        Docker::connect_with_local_defaults().context("Failed to connect to Docker daemon")?;

    // Parse compose file to extract project name and service names
    let compose_info = parse_docker_compose_file(&compose_file)?;
    let project_name = compose_info.project_name;
    let service_names = compose_info.service_names;

    // List all containers
    let options = ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };

    let containers = docker
        .list_containers(Some(options))
        .await
        .context("Failed to list containers")?;

    // Find and remove orphaned containers
    for container in containers {
        let Some(labels) = container.labels else {
            continue;
        };

        // Check if container belongs to current project
        let Some(container_project) = labels.get("com.docker.compose.project") else {
            continue;
        };

        if container_project != &project_name {
            continue;
        }
        // Check if service still exists in compose file
        let Some(service_name) = labels.get("com.docker.compose.service") else {
            continue;
        };
        if service_names.contains(service_name) {
            continue;
        }
        // Service no longer exists in compose file, remove the container
        let Some(container_id) = container.id else {
            continue;
        };

        if dry_run {
            println!("would remove orphaned container {service_name} {container_id}");
        } else {
            println!("removing orphaned container {service_name} {container_id}");
            docker
                .remove_container(
                    &container_id,
                    Some(RemoveContainerOptions {
                        v: true,
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
                .with_context(|| format!("Failed to remove container {}", container_id))?;
        }
    }

    Ok(())
}

/// Docker container config.v2.json structure
#[derive(Deserialize)]
struct ContainerConfig {
    #[serde(rename = "Config")]
    config: Option<ContainerConfigInner>,
}

#[derive(Deserialize)]
struct ContainerConfigInner {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

/// Remove orphaned containers without requiring Docker daemon (offline mode)
///
/// This function directly reads Docker's data directory to find and remove
/// orphaned containers. It should be run BEFORE dockerd starts to prevent
/// orphaned containers from starting.
pub fn remove_orphans_direct(
    compose_file: impl AsRef<Path>,
    docker_root: impl AsRef<Path>,
    dry_run: bool,
) -> Result<()> {
    // Parse compose file to extract project name and service names
    let compose_info = parse_docker_compose_file(&compose_file)?;
    let project_name = &compose_info.project_name;
    let service_names = &compose_info.service_names;

    let containers_dir = docker_root.as_ref().join("containers");
    if !containers_dir.exists() {
        return Ok(());
    }

    // Iterate through all container directories
    let entries = fs::read_dir(&containers_dir).with_context(|| {
        format!(
            "Failed to read containers directory: {}",
            containers_dir.display()
        )
    })?;

    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let container_dir = entry.path();

        if !container_dir.is_dir() {
            continue;
        }

        let container_id = container_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        // Read config.v2.json
        let config_path = container_dir.join("config.v2.json");
        if !config_path.exists() {
            continue;
        }

        let config_content = match fs::read_to_string(&config_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Warning: Failed to read {}: {}", config_path.display(), e);
                continue;
            }
        };

        let config: ContainerConfig = match serde_json::from_str(&config_content) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Warning: Failed to parse {}: {}", config_path.display(), e);
                continue;
            }
        };

        let Some(inner_config) = config.config else {
            continue;
        };

        let Some(labels) = inner_config.labels else {
            continue;
        };

        // Check if container belongs to current project
        let Some(container_project) = labels.get("com.docker.compose.project") else {
            continue;
        };

        if container_project != project_name {
            continue;
        }

        // Check if service still exists in compose file
        let Some(service_name) = labels.get("com.docker.compose.service") else {
            continue;
        };

        if service_names.contains(service_name) {
            continue;
        }

        // Service no longer exists in compose file, remove the container directory
        let short_id = &container_id[..12.min(container_id.len())];

        if dry_run {
            println!("would remove orphaned container {service_name} {short_id}");
        } else {
            println!("removing orphaned container {service_name} {short_id}");
            fs::remove_dir_all(&container_dir).with_context(|| {
                format!(
                    "Failed to remove container directory: {}",
                    container_dir.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `include:` merges another file's services into the same project, and
    /// Compose starts them. This parser cannot see them, so before the fix
    /// every one of them looked like an orphan and `remove_orphans_direct`
    /// deleted the live container's directory on every boot -- silently, since
    /// `dstack-prepare.sh` runs the command with `|| true`.
    ///
    /// Verified against the real resolver: `docker compose config --format
    /// json` on this file reports project `e2demo` with services `main` and
    /// `sidecar`.
    #[test]
    fn an_included_service_is_not_treated_as_an_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("e2demo");
        fs::create_dir_all(&project).unwrap();
        let compose_file = project.join("docker-compose.yaml");
        fs::write(
            &compose_file,
            "name: e2demo\ninclude:\n  - included.yaml\nservices:\n  main:\n    image: busybox\n",
        )
        .unwrap();

        let docker_root = dir.path().join("docker");
        let container = docker_root.join("containers").join("ccccccccccccdddd");
        fs::create_dir_all(&container).unwrap();
        fs::write(
            container.join("config.v2.json"),
            r#"{"Config":{"Labels":{"com.docker.compose.project":"e2demo","com.docker.compose.service":"sidecar"}}}"#,
        )
        .unwrap();

        let result = remove_orphans_direct(&compose_file, &docker_root, false);
        assert!(
            container.exists(),
            "the included service's container directory was deleted"
        );
        assert!(
            result.is_err(),
            "an unresolvable compose file must be reported, not silently skipped"
        );
    }

    /// The common case still works: a service really dropped from the compose
    /// file is still cleaned up.
    #[test]
    fn a_dropped_service_is_still_removed() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("e2demo");
        fs::create_dir_all(&project).unwrap();
        let compose_file = project.join("docker-compose.yaml");
        fs::write(
            &compose_file,
            "name: e2demo\nservices:\n  main:\n    image: busybox\n",
        )
        .unwrap();

        let docker_root = dir.path().join("docker");
        let container = docker_root.join("containers").join("ccccccccccccdddd");
        fs::create_dir_all(&container).unwrap();
        fs::write(
            container.join("config.v2.json"),
            r#"{"Config":{"Labels":{"com.docker.compose.project":"e2demo","com.docker.compose.service":"gone"}}}"#,
        )
        .unwrap();

        remove_orphans_direct(&compose_file, &docker_root, false).unwrap();
        assert!(!container.exists());
    }

    /// Docker reads the part before the first `/` as a registry host only when
    /// it looks like one. Getting this wrong in either direction matters: a
    /// false "Hub" costs a legitimate deployment its pull-through cache, and a
    /// false "not Hub" hands the host an image it can substitute.
    #[test]
    fn a_reference_resolves_to_hub_only_without_a_registry_host() {
        for image in ["nginx", "nginx:1.25", "library/nginx", "myorg/app:v1"] {
            assert!(resolves_to_docker_hub(image), "{image}");
        }
        for image in ["docker.io/library/nginx", "index.docker.io/org/app:v1"] {
            assert!(resolves_to_docker_hub(image), "{image}");
        }
        for image in [
            "ghcr.io/org/app:v1",
            "localhost:5000/app",
            "localhost/app",
            "reg.example.com/app:v1",
            "registry:5000/app",
        ] {
            assert!(!resolves_to_docker_hub(image), "{image}");
        }
    }

    #[test]
    fn only_undigested_hub_images_are_reported() {
        let unpinned = unpinned_hub_images(
            "services:\n  \
             tagged:\n    image: nginx:1.25\n  \
             pinned:\n    image: nginx@sha256:aa\n  \
             elsewhere:\n    image: ghcr.io/org/app:v1\n",
        )
        .unwrap();
        assert_eq!(
            unpinned,
            vec![UnpinnedImage {
                service: "tagged".into(),
                image: "nginx:1.25".into()
            }]
        );
    }

    /// A built service pulls its `FROM` through the same mirror, and the
    /// Dockerfile is not in this file, so its base image cannot be vouched for
    /// however the `image:` alongside it is written.
    #[test]
    fn a_built_service_is_reported_whatever_its_image_field_says() {
        let unpinned =
            unpinned_hub_images("services:\n  api:\n    build: .\n    image: api@sha256:aa\n")
                .unwrap();
        assert_eq!(
            unpinned,
            vec![UnpinnedImage {
                service: "api".into(),
                image: "build".into()
            }]
        );
    }

    /// `include:` brings in services this parser never sees, so the answer
    /// "everything is pinned" would be a guess.
    #[test]
    fn an_unenumerable_compose_file_is_an_error() {
        assert!(unpinned_hub_images(
            "include:\n  - other.yaml\nservices:\n  api:\n    image: nginx@sha256:aa\n"
        )
        .is_err());
        assert!(unpinned_hub_images("services:\n  api:\n    image: [nginx]\n").is_err());
        assert!(unpinned_hub_images("name: app\n").is_err());
    }

    #[test]
    fn test_yaml_anchor_parsing() {
        // Test that yaml-rust2 can parse YAML anchors and aliases
        let yaml_with_anchors = r#"
name: test-project
services:
  common: &common-config
    image: ubuntu:latest
    restart: unless-stopped

  service1:
    <<: *common-config
    container_name: service1

  service2:
    <<: *common-config
    container_name: service2

  service3:
    image: nginx:latest
"#;

        let yaml_docs = YamlLoader::load_from_str(yaml_with_anchors).unwrap();
        let yaml_doc = yaml_docs.first().unwrap();

        // Extract project name
        let project_name = yaml_doc["name"].as_str().unwrap();
        assert_eq!(project_name, "test-project");

        // Extract service names
        let services = match &yaml_doc["services"] {
            Yaml::Hash(m) => m,
            _ => panic!("services should be a hash"),
        };

        let service_names: std::collections::HashSet<String> = services
            .keys()
            .filter_map(|k| k.as_str().map(|s| s.to_string()))
            .collect();

        // Verify all services are parsed including the anchor definition
        assert_eq!(service_names.len(), 4);
        assert!(service_names.contains("common"));
        assert!(service_names.contains("service1"));
        assert!(service_names.contains("service2"));
        assert!(service_names.contains("service3"));

        // Verify that anchors are resolved
        // Note: yaml-rust2 parses anchors but doesn't auto-expand merge keys
        // The merge key "<<" will contain the referenced hash
        let service1 = &yaml_doc["services"]["service1"];
        assert_eq!(service1["container_name"].as_str().unwrap(), "service1");

        // Verify the merge key contains the anchor content
        if let Yaml::Hash(merge_content) = &service1["<<"] {
            assert_eq!(
                merge_content[&Yaml::String("image".to_string())]
                    .as_str()
                    .unwrap(),
                "ubuntu:latest"
            );
            assert_eq!(
                merge_content[&Yaml::String("restart".to_string())]
                    .as_str()
                    .unwrap(),
                "unless-stopped"
            );
        } else {
            panic!("merge key should contain hash");
        }
    }

    #[test]
    fn test_yaml_simple_anchor_alias() {
        // Test simple anchor and alias without merge keys
        let yaml_simple_anchor = r#"
defaults: &defaults
  timeout: 30
  retries: 3

service1:
  name: web
  config: *defaults

service2:
  name: api
  config: *defaults
"#;

        let yaml_docs = YamlLoader::load_from_str(yaml_simple_anchor).unwrap();
        let yaml_doc = yaml_docs.first().unwrap();

        // Verify alias points to the same content
        let service1_config = &yaml_doc["service1"]["config"];
        let service2_config = &yaml_doc["service2"]["config"];

        assert_eq!(service1_config["timeout"].as_i64().unwrap(), 30);
        assert_eq!(service1_config["retries"].as_i64().unwrap(), 3);
        assert_eq!(service2_config["timeout"].as_i64().unwrap(), 30);
        assert_eq!(service2_config["retries"].as_i64().unwrap(), 3);
    }

    #[test]
    fn test_yaml_without_anchors() {
        let yaml_simple = r#"
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
"#;

        let yaml_docs = YamlLoader::load_from_str(yaml_simple).unwrap();
        let yaml_doc = yaml_docs.first().unwrap();

        let services = match &yaml_doc["services"] {
            Yaml::Hash(m) => m,
            _ => panic!("services should be a hash"),
        };

        let service_names: std::collections::HashSet<String> = services
            .keys()
            .filter_map(|k| k.as_str().map(|s| s.to_string()))
            .collect();

        assert_eq!(service_names.len(), 2);
        assert!(service_names.contains("web"));
        assert!(service_names.contains("db"));
    }

    #[test]
    fn test_parse_real_compose_file() {
        // Test with the real local-key-provider/build/docker-compose.yaml
        let compose_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../local-key-provider/build/docker-compose.yaml"
        );

        let compose_info = parse_docker_compose_file(compose_path).unwrap();

        // Verify service names are correctly extracted
        assert_eq!(compose_info.service_names.len(), 2);
        assert!(compose_info.service_names.contains("aesmd"));
        assert!(compose_info.service_names.contains("local-key-provider"));

        // Note: x-common is an anchor definition, not a service, so it should not be in service_names
        assert!(!compose_info.service_names.contains("x-common"));

        // Project name defaults to the Compose file's parent directory.
        assert_eq!(compose_info.project_name, "build");
    }
}
