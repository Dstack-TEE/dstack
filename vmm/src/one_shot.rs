// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::app::{Image, VmConfig, VmWorkDir};
use crate::config::Config;
use crate::main_service;
use anyhow::{Context, Result};

pub async fn run_one_shot(
    vm_config_path: &str,
    config: Config,
    workdir_option: Option<String>,
    dry_run: bool,
) -> Result<()> {
    use dstack_types::AppCompose;
    use dstack_vmm_rpc::VmConfiguration;
    use main_service::create_manifest_from_vm_config;

    // Dynamically allocate CID by scanning running QEMU processes (ps aux method)
    let mut existing_cids = Vec::new();
    if let Ok(output) = std::process::Command::new("ps").args(["aux"]).output() {
        let ps_output = String::from_utf8_lossy(&output.stdout);
        let qemu_lines: Vec<&str> = ps_output
            .lines()
            .filter(|line| line.contains("qemu-system-x86_64") && line.contains("guest-cid"))
            .collect();

        for line in &qemu_lines {
            if let Some(cid_part) = line.split("guest-cid=").nth(1) {
                if let Some(cid_str) = cid_part.split_whitespace().next() {
                    if let Ok(cid) = cid_str.parse::<u32>() {
                        existing_cids.push(cid);
                    }
                }
            }
        }
    }

    // Allocate a free CID in the configured range
    let mut one_shot_cid = config.cvm.cid_start;
    while existing_cids.contains(&one_shot_cid) {
        one_shot_cid += 1;
        if one_shot_cid >= config.cvm.cid_start + config.cvm.cid_pool_size {
            anyhow::bail!(
                "CID pool exhausted - too many VMs running. Found CIDs: {:?}",
                existing_cids
            );
        }
    }

    println!(
        "# Allocated CID: {} (found {} existing QEMU VMs with CIDs: {:?})",
        one_shot_cid,
        existing_cids.len(),
        existing_cids
    );

    println!("# One-shot VM execution mode");
    println!("# Configuration: {}", vm_config_path);

    // Read and parse the VM configuration file
    let vm_config_json = fs_err::read_to_string(vm_config_path)
        .with_context(|| format!("Failed to read VM configuration file: {}", vm_config_path))?;

    // Parse VM configuration
    let vm_config: VmConfiguration = serde_json::from_str(&vm_config_json)
        .with_context(|| format!("Failed to parse VM configuration from: {}", vm_config_path))?;

    // Calculate compose_hash using the same logic as main_service
    let compose_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&vm_config.compose_file);
        hex::encode(hasher.finalize())
    };

    // Create manifest using shared logic
    let manifest = create_manifest_from_vm_config(vm_config.clone(), &config.cvm)?;

    // Load image
    let image_path = config.image_path.join(&manifest.image);
    let image = Image::load(&image_path)
        .with_context(|| format!("Failed to load image: {}", image_path.display()))?;

    // Create or use specified workdir and setup files
    let workdir_path = match workdir_option {
        Some(workdir_str) => {
            let workdir_path = std::path::PathBuf::from(workdir_str);
            fs_err::create_dir_all(&workdir_path)
                .with_context(|| format!("Failed to create workdir: {}", workdir_path.display()))?;
            workdir_path
        }
        None => {
            // Create a persistent directory in current working directory
            let vm_name = &manifest.name;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let workdir_name = format!("dstack-oneshot-{}-{}", vm_name, timestamp);
            let workdir_path = std::env::current_dir()?.join(workdir_name);
            fs_err::create_dir_all(&workdir_path)
                .with_context(|| format!("Failed to create workdir: {}", workdir_path.display()))?;
            workdir_path
        }
    };

    let vm_work_dir = VmWorkDir::new(&workdir_path);

    vm_work_dir
        .put_manifest(&manifest)
        .context("Failed to write manifest")?;

    // Setup shared directory and files
    let shared_dir = vm_work_dir.shared_dir();
    fs_err::create_dir_all(&shared_dir).context("Failed to create shared directory")?;

    // Create app compose file content and parse AppCompose instance
    let (app_compose_content, app_compose) = if vm_config.compose_file.is_empty() {
        // Create default compose JSON directly as string
        let gateway_enabled = !vm_config.gateway_urls.is_empty();
        let kms_enabled = !vm_config.kms_urls.is_empty();

        let default_compose = format!(
            r#"{{
"manifest_version": 1,
"name": "{}",
"runner": "none",
"gateway_enabled": {},
"tproxy_enabled": false,
"kms_enabled": {},
"public_logs": false,
"public_sysinfo": false,
"public_tcbinfo": true,
"local_key_provider_enabled": false,
"no_instance_id": false,
"secure_time": true,
"features": [],
"allowed_envs": []
}}"#,
            vm_config.name, gateway_enabled, kms_enabled
        );

        // Parse the default compose to get AppCompose instance for gateway_enabled() call
        let app_compose: AppCompose =
            serde_json::from_str(&default_compose).context("Failed to parse default AppCompose")?;

        (default_compose, app_compose)
    } else {
        // Parse AppCompose with enhanced error handling for flatten issues
        match serde_json::from_str::<AppCompose>(&vm_config.compose_file) {
            Ok(compose) => (vm_config.compose_file.clone(), compose),
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("can only flatten structs and maps") {
                    anyhow::bail!(
                        "AppCompose flatten error when parsing compose_file: {}

This error occurs because the AppCompose struct has a flattened field for gateway settings.
The issue is likely in the compose_file content:

Common causes:
1. 'gateway_enabled' or 'tproxy_enabled' fields have wrong type (should be boolean)
2. Boolean fields are provided as strings (\"true\" instead of true)
3. Missing quotes around boolean values in JSON

Example of correct compose_file structure:
{{
\"manifest_version\": 1,
\"name\": \"my-app\",
\"runner\": \"none\",
\"gateway_enabled\": true,
\"tproxy_enabled\": false,
\"kms_enabled\": false
}}

Debug: Compose file content (first 200 chars):
{}",
                        error_msg,
                        if vm_config.compose_file.len() > 200 {
                            format!("{}...", &vm_config.compose_file[..200])
                        } else {
                            vm_config.compose_file.clone()
                        }
                    );
                }

                return Err(e).with_context(|| {
                    format!(
                        "Failed to parse compose_file as AppCompose: {}

Compose file content (first 200 chars):
{}",
                        error_msg,
                        if vm_config.compose_file.len() > 200 {
                            format!("{}...", &vm_config.compose_file[..200])
                        } else {
                            vm_config.compose_file.clone()
                        }
                    )
                });
            }
        }
    };

    // Write the JSON string directly (no serialization needed)
    fs_err::write(vm_work_dir.app_compose_path(), app_compose_content)
        .context("Failed to write app compose file")?;

    // Write other files if present
    if !vm_config.encrypted_env.is_empty() {
        fs_err::write(vm_work_dir.encrypted_env_path(), &vm_config.encrypted_env)
            .context("Failed to write encrypted env")?;
    }

    if !vm_config.user_config.is_empty() {
        fs_err::write(vm_work_dir.user_config_path(), &vm_config.user_config)
            .context("Failed to write user config")?;
    }

    // Create missing files that VMM's prepare_work_dir() and sync_dynamic_config() create

    // 1. Create .instance_info (needed for mrconfigid)
    let instance_info = serde_json::json!({
        "instance_id_seed": "4befb40617034796ce9aad5b07b812359d8817bd", // Use a fixed seed for one-shot
        "instance_id": "", // Empty like in the successful VM
        "app_id": &manifest.app_id
    });
    fs_err::write(
        vm_work_dir.instance_info_path(),
        serde_json::to_string(&instance_info)?,
    )
    .context("Failed to write instance info")?;

    // 2. Create .sys-config.json (critical for 0.5.x VMs)
    // Use manifest URLs if available, fallback to config URLs (matching VMM's sync_dynamic_config logic)
    let kms_urls = if manifest.kms_urls.is_empty() {
        config.cvm.kms_urls.clone()
    } else {
        manifest.kms_urls.clone()
    };
    let gateway_urls = if manifest.gateway_urls.is_empty() {
        config.cvm.gateway_urls.clone()
    } else {
        manifest.gateway_urls.clone()
    };

    let sys_config = serde_json::json!({
        "kms_urls": kms_urls,
        "gateway_urls": gateway_urls,
        "pccs_url": config.cvm.pccs_url,
        "docker_registry": config.cvm.docker_registry,
        "host_api_url": format!("vsock://2:{}/api", config.host_api.port),
        "vm_config": serde_json::to_string(&dstack_types::VmConfig {
            spec_version: 1,
            os_image_hash: image.digest.as_ref()
                .and_then(|d| hex::decode(d).ok())
                .unwrap_or_default(),
            cpu_count: manifest.vcpu,
            memory_size: manifest.memory as u64 * 1024 * 1024,
            qemu_single_pass_add_pages: config.cvm.qemu_single_pass_add_pages,
            pic: config.cvm.qemu_pic,
            qemu_version: config.cvm.qemu_version.clone(),
            pci_hole64_size: config.cvm.qemu_pci_hole64_size,
            hugepages: manifest.hugepages,
            num_gpus: manifest.gpus.as_ref().map_or(0, |g| g.gpus.len() as u32),
            num_nvswitches: manifest.gpus.as_ref().map_or(0, |g| g.bridges.len() as u32),
            hotplug_off: config.cvm.qemu_hotplug_off,
            image: Some(manifest.image.clone()),
        })?
    });
    let sys_config_path = vm_work_dir.shared_dir().join(".sys-config.json");
    fs_err::write(&sys_config_path, serde_json::to_string(&sys_config)?)
        .context("Failed to write sys config")?;

    // Create vm-state.json with initial state
    vm_work_dir
        .set_started(false)
        .context("Failed to create vm-state.json")?;

    // Get GPU config from the manifest (already processed)
    let gpus = manifest.gpus.as_ref().cloned().unwrap_or_default();

    // Build VM config and generate QEMU command

    let vm_builder_config = VmConfig {
        manifest: manifest.clone(),
        image,
        cid: one_shot_cid, // Avoid conflict with existing VMs
        workdir: workdir_path.clone(),
        gateway_enabled: app_compose.gateway_enabled(),
    };

    let process_configs = vm_builder_config
        .config_qemu(&workdir_path, &config.cvm, &gpus)
        .context("Failed to build QEMU configuration")?;

    // Get the main QEMU process config (first in the list)
    let process_config = process_configs
        .into_iter()
        .next()
        .context("No QEMU process configuration generated")?;

    // Build the QEMU command
    let mut full_command = vec![process_config.command.clone()];
    full_command.extend(process_config.args.clone());

    println!("# Working directory: {}", workdir_path.display());
    println!("# Compose hash: {}", compose_hash);
    println!("# App ID: {}", manifest.app_id);
    println!("# VM ID: {}", manifest.id);
    println!("#");
    println!("# QEMU Command:");
    println!("{}", full_command.join(" "));

    if dry_run {
        println!("# Dry run mode - QEMU command not executed");
        println!(
            "# To execute, run: --one-shot {} (without --dry-run)",
            vm_config_path
        );
    } else {
        println!("# Executing QEMU...");

        // Change working directory to match supervisor process behavior
        std::env::set_current_dir(&workdir_path).context("Failed to change working directory")?;

        let mut cmd = std::process::Command::new(&process_config.command);
        cmd.args(&process_config.args);

        // Apply environment variables from ProcessConfig
        if !process_config.env.is_empty() {
            cmd.envs(&process_config.env);
        }

        // Configure stdio to match supervisor behavior
        if !process_config.stdout.is_empty() {
            let stdout_file = std::fs::File::create(&process_config.stdout)
                .context("Failed to create stdout file")?;
            cmd.stdout(stdout_file);
        }
        if !process_config.stderr.is_empty() {
            let stderr_file = std::fs::File::create(&process_config.stderr)
                .context("Failed to create stderr file")?;
            cmd.stderr(stderr_file);
        }

        cmd.current_dir(&workdir_path);
        cmd.stdin(std::process::Stdio::null());

        // Execute QEMU command
        let status = cmd.status().context("Failed to execute QEMU command")?;

        if status.success() {
            println!("# QEMU execution completed successfully");
        } else {
            eprintln!("# QEMU exited with status: {}", status);

            // Show output files if they exist
            if !process_config.stdout.is_empty() {
                if let Ok(stdout_content) = fs_err::read_to_string(&process_config.stdout) {
                    if !stdout_content.trim().is_empty() {
                        eprintln!("# QEMU stdout output:");
                        eprintln!("{}", stdout_content);
                    }
                }
            }
            if !process_config.stderr.is_empty() {
                if let Ok(stderr_content) = fs_err::read_to_string(&process_config.stderr) {
                    if !stderr_content.trim().is_empty() {
                        eprintln!("# QEMU stderr output:");
                        eprintln!("{}", stderr_content);
                    }
                }
            }

            eprintln!("# Try running with --dry-run to check the generated command");
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}
