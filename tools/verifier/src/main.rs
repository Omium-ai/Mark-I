//! mark1-verifier CLI — the standalone leg of 08 §7.7 (`mark1
//! verify-receipts` wraps this binary: same code, same verdicts). Every
//! input is a local file and the exit code IS the verdict:
//! 0 chain valid; 5 any defect (defects are enumerated, never summarized
//! away); 2 usage (clap's own); 1 I/O or malformed input.

// The report is this binary's product and stdout is its contract (08 §7.7
// "stdout (--json)") — the workspace print_stdout denial targets daemons and
// hot paths, and 13 §2.2 sanctions a justified targeted allow.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use mark1_verifier::{load_chain, load_keys, load_witness, parse_anchor, verify, Options, Report};

const EXIT_DEFECT: u8 = 5;
const EXIT_INPUT: u8 = 1;

#[derive(Parser)]
#[command(name = "mark1-verifier", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a chain export offline: chain walk, checkpoint Merkle +
    /// inclusion paths, dual signatures under the key manifest's rotation
    /// windows, witness-head cross-check.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// Chain export, one receipt row per line (JSONL).
    #[arg(long)]
    chain: PathBuf,
    /// Local snapshot of the public key manifest (08 §3.5) — offline means a
    /// local file by design, never a fetch.
    #[arg(long)]
    keys: PathBuf,
    /// Local witness snapshot: the heads Omium cannot edit.
    #[arg(long)]
    witness: Option<PathBuf>,
    /// Seq of the export's first row (mid-chain exports).
    #[arg(long, default_value_t = 1)]
    start_seq: u64,
    /// Expected predecessor hash (64 hex chars) when starting mid-chain.
    #[arg(long, value_parser = parse_prev_hash)]
    prev_hash: Option<[u8; 32]>,
    /// Emit the report as JSON (08 §7.7's stdout shape).
    #[arg(long)]
    json: bool,
}

// value_parser so a malformed anchor is a USAGE error (exit 2), not an input
// error — the operator mistyped a flag, no file was ever wrong.
fn parse_prev_hash(s: &str) -> Result<[u8; 32], String> {
    parse_anchor(s).ok_or_else(|| "expected 64 hex characters (a 32-byte hash)".to_string())
}

fn main() -> ExitCode {
    let Cli {
        command: Command::Verify(args),
    } = Cli::parse();
    match run(&args) {
        Ok(report) => {
            if args.json {
                match serde_json::to_string(&report) {
                    Ok(json) => println!("{json}"),
                    // Unreachable for this type (string keys, no fallible
                    // serializers), but an error path is never a panic path.
                    Err(e) => {
                        eprintln!("mark1-verifier: report serialisation failed: {e}");
                        return ExitCode::from(EXIT_INPUT);
                    }
                }
            } else {
                println!("{report}");
            }
            if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_DEFECT)
            }
        }
        Err(e) => {
            eprintln!("mark1-verifier: {e}");
            ExitCode::from(EXIT_INPUT)
        }
    }
}

fn run(args: &VerifyArgs) -> Result<Report, mark1_verifier::InputError> {
    let export = load_chain(&args.chain)?;
    let ring = load_keys(&args.keys)?;
    let witness = args.witness.as_deref().map(load_witness).transpose()?;
    verify(
        &export,
        &ring,
        witness.as_ref(),
        &Options {
            start_seq: args.start_seq,
            anchor_prev: args.prev_hash,
        },
    )
}
