// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Stream compute hash digest of stdin and output the original data to stdout. The digest is output to stderr.
use std::io::{Read, Write};

use anyhow::{Context, Result};
use blake2::{
    digest::consts::{U32, U64},
    Blake2b, Blake2s,
};
use clap::{Parser, ValueEnum};
use fs_err as fs;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct App {
    /// Hash algorithm
    #[arg(value_enum)]
    algorithm: Algorithm,

    /// Binary output
    #[arg(short, long)]
    binary: bool,

    /// Input file. Default is stdin.
    #[arg(short, long)]
    input: Option<String>,

    /// Output file
    #[arg(short, long)]
    output: Option<String>,

    /// Hash file. Default is stderr.
    #[arg(short, long)]
    to: Option<String>,
}

#[derive(ValueEnum, Debug, Clone)]
enum Algorithm {
    Sha256,
    Sha512,
    Sha384,
    Sha512_224,
    Sha512_256,
    Sha224,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2b256,
    Blake2b512,
    Blake2s256,
}

impl App {
    fn compute<Hasher: Digest>(&self) -> Result<()> {
        struct BlackHole;
        impl Write for BlackHole {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; 1024 * 32];
        let input: &mut dyn Read = match &self.input {
            Some(input_file) => {
                if input_file == "-" {
                    &mut std::io::stdin()
                } else {
                    let file = fs::File::open(input_file).context("Failed to open input file")?;
                    &mut { file }
                }
            }
            None => &mut std::io::stdin(),
        };
        let output: &mut dyn Write = match &self.output {
            Some(output_file) => match output_file.as_str() {
                "-" => &mut std::io::stdout(),
                "!" => &mut BlackHole,
                _ => {
                    let file =
                        fs::File::create(output_file).context("Failed to open output file")?;
                    &mut { file }
                }
            },
            None => &mut std::io::stdout(),
        };
        let to: &mut dyn Write = match &self.to {
            Some(to_file) => {
                if to_file == "-" {
                    &mut std::io::stdout()
                } else {
                    let file = fs::File::create(to_file).context("Failed to open hash file")?;
                    &mut { file }
                }
            }
            None => &mut std::io::stderr(),
        };
        loop {
            let len = input
                .read(&mut buffer)
                .context("Failed to read from stdin")?;
            if len == 0 {
                break;
            }
            hasher.update(&buffer[..len]);
            output
                .write_all(&buffer[..len])
                .context("Failed to write to stdout")?;
        }
        let digest = hasher.finalize();
        if self.binary {
            to.write_all(&digest)
                .context("Failed to write hash to file")?;
        } else {
            write!(to, "{}", hex_fmt::HexFmt(&digest)).context("Failed to write hash to file")?;
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let app = App::parse();
    match app.algorithm {
        Algorithm::Sha256 => {
            app.compute::<Sha256>()?;
        }
        Algorithm::Sha512 => {
            app.compute::<Sha512>()?;
        }
        Algorithm::Sha384 => {
            app.compute::<Sha384>()?;
        }
        Algorithm::Sha512_224 => {
            app.compute::<Sha512_224>()?;
        }
        Algorithm::Sha512_256 => {
            app.compute::<Sha512_256>()?;
        }
        Algorithm::Sha224 => {
            app.compute::<Sha224>()?;
        }
        Algorithm::Keccak224 => {
            app.compute::<Keccak224>()?;
        }
        Algorithm::Keccak256 => {
            app.compute::<Keccak256>()?;
        }
        Algorithm::Keccak384 => {
            app.compute::<Keccak384>()?;
        }
        Algorithm::Keccak512 => {
            app.compute::<Keccak512>()?;
        }
        Algorithm::Sha3_224 => {
            app.compute::<Sha3_224>()?;
        }
        Algorithm::Sha3_256 => {
            app.compute::<Sha3_256>()?;
        }
        Algorithm::Sha3_384 => {
            app.compute::<Sha3_384>()?;
        }
        Algorithm::Sha3_512 => {
            app.compute::<Sha3_512>()?;
        }
        Algorithm::Blake2b256 => {
            app.compute::<Blake2b<U32>>()?;
        }
        Algorithm::Blake2b512 => {
            app.compute::<Blake2b<U64>>()?;
        }
        Algorithm::Blake2s256 => {
            app.compute::<Blake2s<U32>>()?;
        }
    }
    Ok(())
}
