//! Command-line tool for DAG-CBOR encoding and decoding.
//!
//! This tool provides utilities for working with DAG-CBOR data:
//! - Encode JSON to DAG-CBOR (hex output)
//! - Decode DAG-CBOR (hex input) to JSON
//! - Validate DAG-CBOR data
//!
//! # Example Usage
//!
//! ```bash
//! # Encode JSON to DAG-CBOR
//! echo '{"foo":"bar"}' | atproto-dasl encode
//!
//! # Decode DAG-CBOR to JSON
//! echo 'a163666f6f63626172' | atproto-dasl decode
//!
//! # Decode with non-strict mode
//! echo 'a163666f6f63626172' | atproto-dasl decode --non-strict
//! ```

use atproto_dasl::{from_slice, from_slice_non_strict, to_vec};
use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};

/// DAG-CBOR encoding and decoding tool
#[derive(Parser)]
#[command(
    name = "atproto-dasl",
    version,
    about = "DAG-CBOR encoding and decoding for AT Protocol",
    long_about = "
A command-line tool for encoding JSON to DAG-CBOR and decoding DAG-CBOR to JSON.

DAG-CBOR is a deterministic subset of CBOR used by IPLD and AT Protocol for
content-addressed data structures.

ENCODING:
  Reads JSON from stdin, outputs DAG-CBOR as hexadecimal to stdout.

DECODING:
  Reads hexadecimal DAG-CBOR from stdin, outputs JSON to stdout.
  Use --non-strict to accept non-canonical encodings.

EXAMPLES:
  # Encode JSON to DAG-CBOR
  echo '{\"text\":\"hello\"}' | atproto-dasl encode

  # Decode DAG-CBOR to JSON
  echo 'a164746578746568656c6c6f' | atproto-dasl decode

  # Decode with non-strict mode (accepts non-canonical data)
  echo 'a164746578746568656c6c6f' | atproto-dasl decode --non-strict
"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode JSON to DAG-CBOR (hex output)
    Encode,
    /// Decode DAG-CBOR (hex input) to JSON
    Decode {
        /// Accept non-canonical encodings
        #[arg(long)]
        non_strict: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Encode => {
            // Read JSON from stdin
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;

            // Parse JSON
            let value: serde_json::Value = serde_json::from_str(&input)?;

            // Encode to DAG-CBOR
            let cbor_bytes = to_vec(&value)?;

            // Output as hex
            for byte in &cbor_bytes {
                print!("{:02x}", byte);
            }
            println!();
        }
        Command::Decode { non_strict } => {
            // Read hex from stdin
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;

            // Parse hex to bytes
            let hex = input.trim();
            let cbor_bytes = hex_to_bytes(hex)?;

            // Decode from DAG-CBOR
            let value: serde_json::Value = if non_strict {
                from_slice_non_strict(&cbor_bytes)?
            } else {
                from_slice(&cbor_bytes)?
            };

            // Output as JSON
            let json = serde_json::to_string_pretty(&value)?;
            io::stdout().write_all(json.as_bytes())?;
            println!();
        }
    }

    Ok(())
}

fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("Hex string must have even length");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)?;
        bytes.push(byte);
    }
    Ok(bytes)
}
