// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// uxrp/rust/src/main.rs
//
// uxrp-loader – CLI tool that loads the XRP eBPF program and drives the
// SPDK polling loop (Aya / Tokio async runtime).

use anyhow::Result;
use clap::Parser;
use log::{info, error};

use uxrp_ebpf::{BpfXrpLoader, XrpContext, XrpVerdict};

#[derive(Parser, Debug)]
#[command(name = "uxrp-loader", about = "uXRP eBPF program loader")]
struct Args {
    /// Path to the compiled eBPF object file (.o)
    #[arg(short, long, default_value = "xrp_prog.o")]
    bpf_obj: String,

    /// ELF section / program name inside the object
    #[arg(short = 'p', long, default_value = "xrp_prog")]
    prog_name: String,

    /// NVMe transport ID (PCIe BDF or NVMe-oF NQN)
    #[arg(short, long, default_value = "0000:00:01.0")]
    trid: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    info!("uXRP Execution Environment starting");
    info!("  BPF object : {}", args.bpf_obj);
    info!("  BPF program: {}", args.prog_name);
    info!("  NVMe TRID  : {}", args.trid);

    // Load the eBPF program
    let mut loader = BpfXrpLoader::new(&args.bpf_obj, &args.prog_name);
    loader.load().map_err(|e| {
        error!("Failed to load eBPF program: {e}");
        e
    })?;

    info!("eBPF program loaded and JIT-compiled");

    // Simulate a completion event and run the eBPF program
    let mut ctx = XrpContext {
        lba:        1024,
        len_blocks: 8,
        status:     0,
        ..Default::default()
    };

    match loader.run(&mut ctx)? {
        XrpVerdict::Done     => info!("eBPF verdict: Done (lba={})", ctx.lba),
        XrpVerdict::Resubmit => info!(
            "eBPF verdict: Resubmit -> lba={} len={}",
            ctx.next_lba, ctx.next_len
        ),
        XrpVerdict::Abort    => {
            error!("eBPF verdict: Abort");
            std::process::exit(1);
        }
    }

    // In a full deployment the async Tokio runtime here would drive the
    // SPDK polling reactor and handle graceful shutdown on SIGINT/SIGTERM.
    tokio::signal::ctrl_c().await?;
    info!("Shutting down uXRP engine");
    Ok(())
}
