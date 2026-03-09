//! Command-line tool for generating CIDs from input data.
//!
//! Computes either a DAG-CBOR record CID or a RAW CID depending on the input
//! content. JSON objects (starting with `{`) produce DAG-CBOR record CIDs,
//! while all other input produces RAW CIDs. This behavior can be overridden
//! with the `--raw` or `--record` flags.
//!
//! # Example Usage
//!
//! ```bash
//! # DAG-CBOR record CID from a JSON argument
//! atpcid '{"text":"hello"}'
//!
//! # Multiple DAG-CBOR record CIDs
//! atpcid '{"text":"hello"}' '{"text":"world"}'
//!
//! # DAG-CBOR record CID from stdin
//! echo '{"text":"hello"}' | atpcid --
//!
//! # RAW CID from binary stdin
//! cat image.jpg | atpcid --
//!
//! # Force RAW CID on JSON input
//! atpcid --raw '{"text":"hello"}'
//!
//! # Force DAG-CBOR record CID from stdin
//! cat data.json | atpcid --record --
//!
//! # RAW CIDs from files
//! atpcid --files --raw image1.jpg image2.jpg
//!
//! # DAG-CBOR record CID from a JSON file
//! atpcid --files --record data.json
//! ```

use atproto_dasl::{compute_cid_for, compute_raw_cid};
use clap::Parser;
use std::io::{self, Read};
use std::path::Path;

/// Compute a CID from input data.
///
/// Accepts one or more input strings as positional arguments, or reads from
/// stdin when no arguments are provided (use `--` to separate from flags).
/// JSON objects produce DAG-CBOR record CIDs; other input produces RAW CIDs.
/// Use `--raw` or `--record` to override auto-detection.
#[derive(Parser)]
#[command(
    name = "atpcid",
    version,
    about = "Compute CIDs from input data",
    long_about = "
Compute a CID (Content Identifier) from input data.

By default, the tool auto-detects the CID type based on the input:
  - Input starting with '{' is treated as a JSON record and produces a
    DAG-CBOR record CID (CIDv1, codec 0x71, SHA-256).
  - All other input produces a RAW CID (CIDv1, codec 0x55, SHA-256).

Use --raw or --record to override auto-detection.

INPUT MODES:
  Positional arguments are processed as individual inputs, each producing
  one CID. Use -- to read from stdin instead of positional arguments.
  Use --files to read file contents from positional argument paths.

EXAMPLES:
  # DAG-CBOR record CID from a JSON argument
  atpcid '{\"text\":\"hello\"}'

  # Multiple CIDs from multiple arguments
  atpcid '{\"text\":\"hello\"}' '{\"text\":\"world\"}'

  # DAG-CBOR record CID from stdin
  echo '{\"text\":\"hello\"}' | atpcid --

  # RAW CID from binary stdin
  cat image.jpg | atpcid --

  # Force RAW CID on JSON input
  atpcid --raw '{\"text\":\"hello\"}'

  # Force DAG-CBOR record CID from stdin
  cat data.json | atpcid --record --

  # RAW CIDs from files
  atpcid --files --raw image1.jpg image2.jpg

  # DAG-CBOR record CID from a JSON file
  atpcid --files --record data.json
"
)]
struct Args {
    /// Input data strings, each producing one CID. When empty, reads from stdin.
    /// With --files, each argument is treated as a file path.
    inputs: Vec<String>,

    /// Force output as a RAW CID (codec 0x55)
    #[arg(long, conflicts_with = "record")]
    raw: bool,

    /// Force output as a DAG-CBOR record CID (codec 0x71)
    #[arg(long, conflicts_with = "raw")]
    record: bool,

    /// Treat positional arguments as file paths and read their contents
    #[arg(long)]
    files: bool,
}

fn compute_and_print(data: &[u8], raw: bool, record: bool) -> anyhow::Result<()> {
    let use_record = if raw {
        false
    } else if record {
        true
    } else {
        first_non_whitespace_byte(data) == Some(b'{')
    };

    let cid = if use_record {
        let text = std::str::from_utf8(data)?;
        let json_value: serde_json::Value = serde_json::from_str(text)?;
        compute_cid_for(&json_value)?
    } else {
        compute_raw_cid(data)
    };

    println!("{cid}");

    Ok(())
}

fn first_non_whitespace_byte(data: &[u8]) -> Option<u8> {
    data.iter().find(|b| !b.is_ascii_whitespace()).copied()
}

fn has_double_dash() -> bool {
    std::env::args_os().any(|arg| arg == "--")
}

fn main() -> anyhow::Result<()> {
    let read_stdin = has_double_dash();
    let args = Args::parse();

    anyhow::ensure!(
        !(read_stdin && args.files),
        "-- and --files cannot be used together"
    );

    if args.files {
        anyhow::ensure!(
            !args.inputs.is_empty(),
            "--files requires at least one file path"
        );
        for path in &args.inputs {
            let data = std::fs::read(Path::new(path))?;
            compute_and_print(&data, args.raw, args.record)?;
        }
    } else if read_stdin {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        compute_and_print(&buf, args.raw, args.record)?;
    } else {
        anyhow::ensure!(
            !args.inputs.is_empty(),
            "no input provided; pass data as arguments, use -- for stdin, or use --files"
        );
        for input in &args.inputs {
            compute_and_print(input.as_bytes(), args.raw, args.record)?;
        }
    }

    Ok(())
}
