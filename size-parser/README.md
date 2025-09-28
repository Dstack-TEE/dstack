# size-parser

A utility crate for parsing and handling memory sizes with serde support.

## Features

- Parse memory size strings with various suffixes (K, M, G, T)
- Support for hexadecimal values (0x prefix)
- Optional serde serialization/deserialization support
- Human-readable formatting
- Type-safe memory size handling

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
size-parser = { path = "../size-parser" }

# For serde support
size-parser = { path = "../size-parser", features = ["serde"] }
```

## Examples

### Basic Usage

```rust
use size_parser::MemorySize;

// Parse from string
let size = MemorySize::parse("2G").unwrap();
assert_eq!(size.bytes(), 2 * 1024 * 1024 * 1024);

// Parse hexadecimal
let size = MemorySize::parse("0x1000").unwrap();
assert_eq!(size.bytes(), 4096);

// Create from bytes
let size = MemorySize::from_bytes(1024);
assert_eq!(size.bytes(), 1024);

// Using FromStr trait
let size: MemorySize = "2G".parse().unwrap();
assert_eq!(size.bytes(), 2 * 1024 * 1024 * 1024);
```

### Supported Formats

- Plain numbers: `"1024"`, `"2048"`
- Hexadecimal: `"0x1000"`, `"0X2000"`
- With suffixes: `"2K"`, `"4M"`, `"1G"`, `"2T"` (case-insensitive)

Suffixes use binary (1024-based) multipliers:
- K/k: 1024 bytes
- M/m: 1024² bytes  
- G/g: 1024³ bytes
- T/t: 1024⁴ bytes

### Human-readable Formatting

```rust
let size = MemorySize::from_bytes(1536);
println!("{}", size); // Prints: "1.5K"

let size = MemorySize::from_bytes(2 * 1024 * 1024 * 1024);
println!("{}", size); // Prints: "2G"
```

### Serde Support (with "serde" feature)

#### Using MemorySize Type

```rust
use size_parser::MemorySize;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Config {
    memory: MemorySize,
}

let config = Config {
    memory: MemorySize::parse("2G").unwrap(),
};

// Serializes as: {"memory": "2G"}
let json = serde_json::to_string(&config).unwrap();

// Can deserialize from various formats
let config: Config = serde_json::from_str(r#"{"memory": "1024M"}"#).unwrap();
```

#### Using Field Attributes with Numeric Types

You can also use serde field attributes to serialize/deserialize memory sizes directly into any numeric type that can be converted to/from u64:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct MyConfig {
    #[serde(with = "size_parser::human_size")]
    memory_size: u64,
    #[serde(with = "size_parser::human_size")]
    buffer_size: usize,
    #[serde(with = "size_parser::human_size")]
    cache_size: u32,
}

let config = MyConfig {
    memory_size: 2 * 1024 * 1024 * 1024, // 2GB
    buffer_size: 512 * 1024,             // 512KB
    cache_size: 64 * 1024,               // 64KB
};

// Serializes as: {"memory_size": "2G", "buffer_size": "512K", "cache_size": "64K"}
let json = serde_json::to_string(&config).unwrap();

// Can deserialize from human-readable formats
let config: MyConfig = serde_json::from_str(r#"{"memory_size": "1G", "buffer_size": "256K", "cache_size": "32K"}"#).unwrap();
assert_eq!(config.memory_size, 1024 * 1024 * 1024);
assert_eq!(config.buffer_size, 256 * 1024);
assert_eq!(config.cache_size, 32 * 1024);
```

**Supported numeric types:**
- `u64`, `u32`, `u16`, `u8` - unsigned integers
- `usize` - platform-dependent unsigned integer
- Any type that implements `TryFrom<u64>` and `Into<u64>`

The generic implementation automatically handles overflow checking and provides clear error messages when values are too large for the target type.

### Compatibility Function

For compatibility with existing code, a standalone function is also provided:

```rust
use size_parser::parse_memory_size;

let bytes = parse_memory_size("2G").unwrap();
assert_eq!(bytes, 2 * 1024 * 1024 * 1024);
```

## License

Apache-2.0
