// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

fn main() {
    if let Err(err) = build_console() {
        panic!("failed to build vmm console: {err}");
    }
}

fn build_console() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let ui_dir = manifest_dir.join("ui");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let output = out_dir.join("console_v1.html");

    emit_rerun_if_changed(&manifest_dir.join("build.rs"))?;
    emit_rerun_tree(&ui_dir)?;

    ensure_command("node", &["--version"], "Node.js")?;
    ensure_command(
        npm_cmd(),
        &["--version"],
        "npm (normally bundled with Node.js)",
    )?;

    if should_run_npm_ci(&ui_dir)? {
        run(
            npm_cmd(),
            &["ci"],
            &ui_dir,
            &[],
            "Install VMM UI dependencies with `npm ci`",
        )?;
    }

    let output_str = output
        .to_str()
        .ok_or("OUT_DIR path contains non-UTF-8 characters")?;
    run(
        "node",
        &["build.mjs"],
        &ui_dir,
        &[("DSTACK_UI_OUT", output_str)],
        "Build VMM UI",
    )?;

    if !output.exists() {
        return Err(format!(
            "UI build succeeded but {} was not created",
            output.display()
        )
        .into());
    }

    Ok(())
}

fn emit_rerun_tree(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(());
    }
    println!("cargo:rerun-if-changed={}", path.display());
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        if entry.file_type()?.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), "node_modules" | "build" | "dist") {
                continue;
            }
            emit_rerun_tree(&child)?;
        } else {
            emit_rerun_if_changed(&child)?;
        }
    }
    Ok(())
}

fn emit_rerun_if_changed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={}", path.display());
    Ok(())
}

fn ensure_command(
    program: &str,
    args: &[&str],
    display_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!(
                "{display_name} is required to build vmm/ui. Please install it first. `{program} {}` failed. stdout: {} stderr: {}",
                args.join(" "),
                stdout.trim(),
                stderr.trim(),
            )
            .into())
        }
        Err(err) => Err(format!(
            "{display_name} is required to build vmm/ui. Please install Node.js and npm first: {err}"
        )
        .into()),
    }
}

fn should_run_npm_ci(ui_dir: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let package_json = ui_dir.join("package.json");
    let package_lock = ui_dir.join("package-lock.json");
    let marker = ui_dir.join("node_modules/.package-lock.json");

    if !marker.exists() {
        return Ok(true);
    }

    let marker_time = modified_time(&marker)?;
    Ok(modified_time(&package_json)? > marker_time || modified_time(&package_lock)? > marker_time)
}

fn modified_time(path: &Path) -> Result<SystemTime, Box<dyn std::error::Error>> {
    Ok(fs::metadata(path)?.modified()?)
}

fn run(
    program: &str,
    args: &[&str],
    cwd: &Path,
    envs: &[(&str, &str)],
    what: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(program);
    command
        .current_dir(cwd)
        .args(args)
        .envs(envs.iter().copied());
    let status = command.status()?;
    if !status.success() {
        return Err(format!("{what} failed with exit status {status}").into());
    }
    Ok(())
}

fn npm_cmd() -> &'static str {
    if cfg!(windows) {
        "npm.cmd"
    } else {
        "npm"
    }
}
