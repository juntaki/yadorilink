//! CLI entry point: `cargo run -p yadorilink-bench -- <scenario> [--size-mb <n>]`.
//! Not wired through `xtask` (that tool's own doc comment scopes it to DST
//! replay and lanes, a `--cfg madsim` deterministic-simulation concern this
//! harness is not) -- see DESIGN.md for the full reasoning and the
//! `bench-l1` cargo alias this crate does add.

use yadorilink_bench::scenario::{RunOptions, Scenario, ALL_SCENARIO_IDS};
use yadorilink_bench::scenarios::l1::L1Scenario;

const DEFAULT_L1_SIZE_MB: u64 = 10 * 1024;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((scenario_id, rest)) = args.split_first() else {
        usage();
        std::process::exit(2);
    };

    match scenario_id.as_str() {
        "list" => {
            println!("scenarios: {}", ALL_SCENARIO_IDS.join(", "));
            println!("implemented: L1");
            Ok(())
        }
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        "L1" => run_l1(rest).await,
        other if ALL_SCENARIO_IDS.contains(&other) => {
            anyhow::bail!(
                "scenario {other} is on the M6 roster but has no runner yet -- only L1 is \
                 implemented in this first slice (see DESIGN.md)"
            )
        }
        other => {
            usage();
            anyhow::bail!("unknown scenario `{other}`")
        }
    }
}

async fn run_l1(args: &[String]) -> anyhow::Result<()> {
    let size_mb = parse_size_mb(args).unwrap_or(DEFAULT_L1_SIZE_MB);
    println!(
        "L1: 10GB-class single file over loopback (two real DaemonState instances, real \
         WireGuard-shaped transport, real block store) -- size {size_mb} MiB"
    );

    let resilio = yadorilink_bench::resilio::ResilioAvailability::detect();
    println!("{}", resilio.describe());
    for line in yadorilink_bench::ceiling::CeilingTools::detect().describe() {
        println!("{line}");
    }

    let opts = RunOptions { file_size_bytes: size_mb * 1024 * 1024 };
    let report = L1Scenario.run(&opts).await?;
    report.print();
    Ok(())
}

fn parse_size_mb(args: &[String]) -> Option<u64> {
    let idx = args.iter().position(|a| a == "--size-mb")?;
    args.get(idx + 1)?.parse().ok()
}

fn usage() {
    eprintln!(
        "yadorilink-bench <scenario> [options]\n\n\
         \x20 list                    list every M6 scenario id and which are implemented\n\
         \x20 L1 [--size-mb <n>]      10GB-class single file transfer (default {DEFAULT_L1_SIZE_MB} MiB)\n"
    );
}
