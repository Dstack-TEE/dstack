use anyhow::{Context, Result};
use dstack_vmm_rpc::VmConfiguration;
use serde_json::{Map, Value};

pub async fn validate_config_file(vm_config_path: &str) -> Result<()> {
    println!("🔍 Validating VM configuration file: {}", vm_config_path);

    // Read the file
    let vm_config_json = match fs_err::read_to_string(vm_config_path) {
        Ok(content) => {
            println!("✅ Successfully read configuration file");
            content
        }
        Err(e) => {
            println!("❌ Failed to read configuration file");
            return Err(e).with_context(|| format!("Failed to read file: {}", vm_config_path));
        }
    };

    // Parse with validation
    let vm_config = match parse_vm_config_with_validation(&vm_config_json, vm_config_path) {
        Ok(config) => {
            println!("✅ JSON structure is valid");
            println!("✅ All required fields are present and correctly typed");
            config
        }
        Err(e) => {
            println!("❌ Configuration validation failed");
            return Err(e);
        }
    };

    // Additional validation information
    println!("\n📋 Configuration Summary:");
    println!("  • Name: {}", vm_config.name);
    println!("  • Image: {}", vm_config.image);
    println!("  • vCPU: {}", vm_config.vcpu);
    println!("  • Memory: {} MB", vm_config.memory);
    println!("  • Disk Size: {} GB", vm_config.disk_size);
    println!("  • Port Mappings: {}", vm_config.ports.len());
    println!("  • Hugepages: {}", vm_config.hugepages);
    println!("  • Pin NUMA: {}", vm_config.pin_numa);
    println!("  • KMS URLs: {}", vm_config.kms_urls.len());
    println!("  • Gateway URLs: {}", vm_config.gateway_urls.len());
    println!("  • Stopped: {}", vm_config.stopped);

    if !vm_config.compose_file.is_empty() {
        println!(
            "  • Compose File: {} characters",
            vm_config.compose_file.len()
        );
        // Try to parse compose file as JSON first
        match serde_json::from_str::<serde_json::Value>(&vm_config.compose_file) {
            Ok(_) => {
                println!("    ✅ Compose file is valid JSON");

                // Now try to parse as AppCompose to catch flatten errors
                match serde_json::from_str::<dstack_types::AppCompose>(&vm_config.compose_file) {
                    Ok(_) => println!("    ✅ Compose file can be parsed as AppCompose"),
                    Err(e) => {
                        println!("    ❌ AppCompose parsing error: {}", e);
                        return Err(anyhow::anyhow!("AppCompose validation failed: {}", e));
                    }
                }
            }
            Err(e) => {
                println!("    ❌ Compose file JSON error: {}", e);
                return Err(anyhow::anyhow!(
                    "Compose file JSON validation failed: {}",
                    e
                ));
            }
        }
    }

    if let Some(gpus) = vm_config.gpus.as_ref() {
        println!("  • GPU Config:");
        println!("    - Attach Mode: {}", gpus.attach_mode);
        println!("    - GPU Count: {}", gpus.gpus.len());
    }

    println!("\n🎉 Configuration file is completely valid!");
    Ok(())
}

pub fn parse_vm_config_with_validation(json_str: &str, file_path: &str) -> Result<VmConfiguration> {
    // First, parse as generic JSON to provide better error messages
    let json_value: Value = serde_json::from_str(json_str)
        .with_context(|| format!("Invalid JSON syntax in file: {}", file_path))?;

    // Validate the JSON structure and provide helpful error messages
    let obj = json_value.as_object().ok_or_else(|| {
        anyhow::anyhow!("Configuration must be a JSON object, not an array or primitive value")
    })?;

    // Check required fields
    validate_required_field(obj, "name", file_path)?;
    validate_required_field(obj, "image", file_path)?;
    validate_numeric_field(obj, "vcpu", file_path)?;
    validate_numeric_field(obj, "memory", file_path)?;
    validate_numeric_field(obj, "disk_size", file_path)?;

    // Validate field types
    validate_string_field(obj, "name", file_path)?;
    validate_string_field(obj, "image", file_path)?;
    validate_string_field_optional(obj, "compose_file", file_path)?;
    validate_string_field_optional(obj, "user_config", file_path)?;
    validate_string_field_optional(obj, "app_id", file_path)?;

    // Validate arrays
    validate_array_field(obj, "ports", file_path)?;
    validate_array_field(obj, "kms_urls", file_path)?;
    validate_array_field(obj, "gateway_urls", file_path)?;

    // Validate boolean fields
    validate_boolean_field_optional(obj, "hugepages", file_path)?;
    validate_boolean_field_optional(obj, "pin_numa", file_path)?;
    validate_boolean_field_optional(obj, "stopped", file_path)?;

    // Validate GPU config if present
    if let Some(gpus_value) = obj.get("gpus") {
        validate_gpu_config(gpus_value, file_path)?;
    }

    // Validate ports if present
    if let Some(ports_value) = obj.get("ports") {
        validate_ports_config(ports_value, file_path)?;
    }

    // Try to catch the specific "flatten" error by attempting a preliminary deserialization
    match serde_json::from_str::<VmConfiguration>(json_str) {
        Ok(config) => Ok(config),
        Err(e) => {
            let error_msg = e.to_string();

            // Check for the specific flatten error
            if error_msg.contains("can only flatten structs and maps") {
                // Check for problematic fields in compose_file that might cause flatten issues
                if let Some(compose_file_value) = obj.get("compose_file") {
                    if let Some(compose_str) = compose_file_value.as_str() {
                        if !compose_str.is_empty() {
                            validate_compose_file_content(compose_str, file_path)?;
                        }
                    }
                }

                anyhow::bail!(
                    "Serde flatten error in '{}': {}\n\
                    \n\
                    This error typically occurs when:\n\
                    1. The 'compose_file' contains invalid JSON structure\n\
                    2. Boolean fields are provided where objects are expected\n\
                    3. The 'compose_file' has incorrect gateway_enabled/tproxy_enabled structure\n\
                    \n\
                    For compose_file, ensure it contains valid JSON like:\n\
                    {{\n\
                      \"manifest_version\": 1,\n\
                      \"name\": \"my-app\",\n\
                      \"runner\": \"none\",\n\
                      \"gateway_enabled\": false\n\
                    }}\n\
                    \n\
                    Or use an empty string \"\" if no compose file is needed.",
                    file_path,
                    error_msg
                );
            }

            // Return with enhanced context for other errors
            Err(e).with_context(|| {
                format!(
                    "Failed to parse VM configuration from '{}'. \n\
                    Original error: {}\n\
                    \n\
                    Common issues:\n\
                    - Use empty string \"\" instead of null for optional text fields\n\
                    - Ensure all numeric fields (vcpu, memory, disk_size) are positive integers\n\
                    - If GPU config is provided, it must have 'attach_mode' field (\"listed\" or \"all\")\n\
                    - Port mappings must have protocol, host_port, vm_port fields\n\
                    - compose_file must be valid JSON or empty string\n\
                    \n\
                    Example minimal config:\n\
                    {{\n\
                      \"name\": \"my-vm\",\n\
                      \"image\": \"base-v0.5.4.qcow2\",\n\
                      \"compose_file\": \"\",\n\
                      \"vcpu\": 2,\n\
                      \"memory\": 4096,\n\
                      \"disk_size\": 20,\n\
                      \"ports\": [],\n\
                      \"encrypted_env\": \"\",\n\
                      \"user_config\": \"\",\n\
                      \"hugepages\": false,\n\
                      \"pin_numa\": false,\n\
                      \"kms_urls\": [],\n\
                      \"gateway_urls\": [],\n\
                      \"stopped\": false\n\
                    }}",
                    file_path, error_msg
                )
            })
        }
    }
}

fn validate_required_field(obj: &Map<String, Value>, field: &str, file_path: &str) -> Result<()> {
    if !obj.contains_key(field) {
        anyhow::bail!("Missing required field '{}' in {}", field, file_path);
    }
    Ok(())
}

fn validate_string_field(obj: &Map<String, Value>, field: &str, file_path: &str) -> Result<()> {
    if let Some(value) = obj.get(field) {
        if value.is_null() {
            anyhow::bail!(
                "Field '{}' in {} cannot be null. Use empty string \"\" instead.",
                field,
                file_path
            );
        }
        if !value.is_string() {
            anyhow::bail!(
                "Field '{}' in {} must be a string, got: {}",
                field,
                file_path,
                value
            );
        }
    }
    Ok(())
}

fn validate_string_field_optional(
    obj: &Map<String, Value>,
    field: &str,
    file_path: &str,
) -> Result<()> {
    if let Some(value) = obj.get(field) {
        if value.is_null() {
            anyhow::bail!(
                "Field '{}' in {} cannot be null. Use empty string \"\" instead or omit the field.",
                field,
                file_path
            );
        }
        if !value.is_string() {
            anyhow::bail!(
                "Field '{}' in {} must be a string, got: {}",
                field,
                file_path,
                value
            );
        }
    }
    Ok(())
}

fn validate_numeric_field(obj: &Map<String, Value>, field: &str, file_path: &str) -> Result<()> {
    if let Some(value) = obj.get(field) {
        if !value.is_number() {
            anyhow::bail!(
                "Field '{}' in {} must be a number, got: {}",
                field,
                file_path,
                value
            );
        }
        if let Some(num) = value.as_u64() {
            if num == 0 {
                anyhow::bail!(
                    "Field '{}' in {} must be greater than 0, got: {}",
                    field,
                    file_path,
                    num
                );
            }
        }
    }
    Ok(())
}

fn validate_array_field(obj: &Map<String, Value>, field: &str, file_path: &str) -> Result<()> {
    if let Some(value) = obj.get(field) {
        if value.is_null() {
            anyhow::bail!(
                "Field '{}' in {} cannot be null. Use empty array [] instead.",
                field,
                file_path
            );
        }
        if !value.is_array() {
            anyhow::bail!(
                "Field '{}' in {} must be an array, got: {}",
                field,
                file_path,
                value
            );
        }
    }
    Ok(())
}

fn validate_boolean_field_optional(
    obj: &Map<String, Value>,
    field: &str,
    file_path: &str,
) -> Result<()> {
    if let Some(value) = obj.get(field) {
        if value.is_null() {
            anyhow::bail!(
                "Field '{}' in {} cannot be null. Use true or false instead or omit the field.",
                field,
                file_path
            );
        }
        if !value.is_boolean() {
            anyhow::bail!(
                "Field '{}' in {} must be a boolean (true or false), got: {}",
                field,
                file_path,
                value
            );
        }
    }
    Ok(())
}

fn validate_gpu_config(gpus_value: &Value, file_path: &str) -> Result<()> {
    if gpus_value.is_null() {
        return Ok(()); // null is acceptable for optional field
    }

    let gpu_obj = gpus_value.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "Field 'gpus' in {} must be an object or null, got: {}",
            file_path,
            gpus_value
        )
    })?;

    // Check attach_mode
    if let Some(attach_mode) = gpu_obj.get("attach_mode") {
        if !attach_mode.is_string() {
            anyhow::bail!(
                "Field 'gpus.attach_mode' in {} must be a string, got: {}",
                file_path,
                attach_mode
            );
        }
        let mode_str = attach_mode.as_str().unwrap();
        if mode_str != "listed" && mode_str != "all" {
            anyhow::bail!(
                "Field 'gpus.attach_mode' in {} must be \"listed\" or \"all\", got: \"{}\"",
                file_path,
                mode_str
            );
        }
    }

    // Check gpus array
    if let Some(gpus_array) = gpu_obj.get("gpus") {
        if !gpus_array.is_array() {
            anyhow::bail!(
                "Field 'gpus.gpus' in {} must be an array, got: {}",
                file_path,
                gpus_array
            );
        }

        for (i, gpu_spec) in gpus_array.as_array().unwrap().iter().enumerate() {
            if let Some(gpu_obj) = gpu_spec.as_object() {
                if let Some(slot) = gpu_obj.get("slot") {
                    if !slot.is_string() {
                        anyhow::bail!(
                            "Field 'gpus.gpus[{}].slot' in {} must be a string, got: {}",
                            i,
                            file_path,
                            slot
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn validate_ports_config(ports_value: &Value, file_path: &str) -> Result<()> {
    if !ports_value.is_array() {
        anyhow::bail!(
            "Field 'ports' in {} must be an array, got: {}",
            file_path,
            ports_value
        );
    }

    for (i, port) in ports_value.as_array().unwrap().iter().enumerate() {
        let port_obj = port.as_object().ok_or_else(|| {
            anyhow::anyhow!(
                "ports[{}] in {} must be an object, got: {}",
                i,
                file_path,
                port
            )
        })?;

        // Check required fields
        for field in &["protocol", "host_port", "vm_port", "host_address"] {
            if let Some(value) = port_obj.get(*field) {
                match *field {
                    "protocol" | "host_address" => {
                        if !value.is_string() {
                            anyhow::bail!(
                                "Field 'ports[{}].{}' in {} must be a string, got: {}",
                                i,
                                field,
                                file_path,
                                value
                            );
                        }
                    }
                    "host_port" | "vm_port" => {
                        if !value.is_number() {
                            anyhow::bail!(
                                "Field 'ports[{}].{}' in {} must be a number, got: {}",
                                i,
                                field,
                                file_path,
                                value
                            );
                        }
                        if let Some(port_num) = value.as_u64() {
                            if port_num == 0 || port_num > 65535 {
                                anyhow::bail!("Field 'ports[{}].{}' in {} must be between 1 and 65535, got: {}", i, field, file_path, port_num);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn validate_compose_file_content(compose_json: &str, file_path: &str) -> Result<()> {
    // Try to parse the compose file content
    let compose_value: Value = serde_json::from_str(compose_json)
        .with_context(|| format!("Invalid JSON in compose_file field in {}", file_path))?;

    let compose_obj = compose_value.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "compose_file in {} must contain a JSON object, got: {}",
            file_path,
            compose_value
        )
    })?;

    // Check for problematic flatten fields that might cause the error
    if let Some(gateway_enabled) = compose_obj.get("gateway_enabled") {
        if !gateway_enabled.is_boolean() && !gateway_enabled.is_null() {
            anyhow::bail!(
                "In compose_file in {}: 'gateway_enabled' must be a boolean (true/false), got: {}. \
                This might be causing the flatten error.",
                file_path, gateway_enabled
            );
        }
    }

    if let Some(tproxy_enabled) = compose_obj.get("tproxy_enabled") {
        if !tproxy_enabled.is_boolean() && !tproxy_enabled.is_null() {
            anyhow::bail!(
                "In compose_file in {}: 'tproxy_enabled' must be a boolean (true/false), got: {}. \
                This might be causing the flatten error.",
                file_path,
                tproxy_enabled
            );
        }
    }

    // Validate other common fields that might cause issues
    if let Some(manifest_version) = compose_obj.get("manifest_version") {
        if !manifest_version.is_number() {
            anyhow::bail!(
                "In compose_file in {}: 'manifest_version' must be a number, got: {}",
                file_path,
                manifest_version
            );
        }
    }

    if let Some(name) = compose_obj.get("name") {
        if !name.is_string() {
            anyhow::bail!(
                "In compose_file in {}: 'name' must be a string, got: {}",
                file_path,
                name
            );
        }
    }

    if let Some(runner) = compose_obj.get("runner") {
        if !runner.is_string() {
            anyhow::bail!(
                "In compose_file in {}: 'runner' must be a string, got: {}",
                file_path,
                runner
            );
        }
    }

    // Check for any fields that are incorrectly structured as objects when they should be primitives
    for (key, value) in compose_obj.iter() {
        if key == "gateway_enabled" || key == "tproxy_enabled" {
            // These are handled by the flatten deserializer, so they might be objects in some cases
            // But check if it's an object with unexpected structure
            if let Some(obj) = value.as_object() {
                for inner_key in obj.keys() {
                    if inner_key != "gateway_enabled" && inner_key != "tproxy_enabled" {
                        anyhow::bail!(
                            "In compose_file in {}: Unexpected field '{}' inside '{}' object. \
                            The flatten deserializer expects only 'gateway_enabled' and 'tproxy_enabled' fields.",
                            file_path, inner_key, key
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
