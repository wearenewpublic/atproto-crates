//! Command-line tool for generating and parsing AT Protocol TIDs.
//!
//! TIDs (Timestamp Identifiers) are 13-character base32-sortable strings that encode
//! a microsecond-precision timestamp with a random clock identifier for collision
//! resistance. This tool supports generating new TIDs, batch generation, parsing
//! existing TIDs, and creating TIDs from specific timestamps.
//!
//! # Example Usage
//!
//! ```bash
//! # Generate a single TID
//! cargo run --features clap --bin atptid
//!
//! # Generate 5 TIDs
//! cargo run --features clap --bin atptid -- -n 5
//!
//! # Parse a TID and display its timestamp
//! cargo run --features clap --bin atptid -- 3mgn37sytoc2c
//!
//! # Validate a TID quietly (exit code 0 = valid, 1 = invalid)
//! cargo run --features clap --bin atptid -- -q 3mgn37sytoc2c
//!
//! # Generate a TID from a microsecond timestamp
//! cargo run --features clap --bin atptid -- 1773067572
//! ```

use std::process;

use atproto_record::tid::Tid;
use clap::Parser;

/// AT Protocol TID Generator and Parser
#[derive(Parser)]
#[command(
    name = "atptid",
    version,
    about = "Generate and parse AT Protocol Timestamp Identifiers (TIDs)",
    long_about = "
A command-line tool for generating and parsing AT Protocol TIDs (Timestamp
Identifiers). TIDs are 13-character base32-sortable strings combining a
microsecond timestamp with a random clock identifier.

MODES:
  Generate:  atptid              Generate a single TID
  Batch:     atptid -n 5         Generate multiple TIDs
  Parse:     atptid <tid>        Parse a TID and display its timestamp
  Validate:  atptid -q <tid>     Validate a TID (exit 1 if invalid)
  From time: atptid <timestamp>  Generate a TID from microsecond timestamp

EXAMPLES:
  atptid
  atptid -n 10
  atptid 3mgn37sytoc2c
  atptid -q 3mgn37sytoc2c
  atptid 1773067572000000
"
)]
struct Args {
    /// TID to parse, or microsecond timestamp to generate a TID from
    input: Option<String>,

    /// Number of TIDs to generate
    #[arg(short = 'n', long)]
    count: Option<usize>,

    /// Quiet mode - validate without output, exit 1 if invalid
    #[arg(short, long)]
    quiet: bool,
}

fn main() {
    let args = Args::parse();

    match args.input {
        None => {
            let count = args.count.unwrap_or(1);
            for _ in 0..count {
                println!("{}", Tid::new());
            }
        }
        Some(input) => {
            if input.chars().all(|c| c.is_ascii_digit()) {
                let timestamp: u64 = input.parse().unwrap_or_else(|_| {
                    eprintln!("error-atproto-record-cli-11 Invalid timestamp: {input}");
                    process::exit(1);
                });
                let tid = Tid::new_with_time(timestamp);
                println!("{tid}");
            } else {
                match Tid::decode(&input) {
                    Ok(tid) => {
                        if !args.quiet {
                            println!("{}", tid.timestamp_micros());
                        }
                    }
                    Err(err) => {
                        if !args.quiet {
                            eprintln!("{err}");
                        }
                        process::exit(1);
                    }
                }
            }
        }
    }
}
