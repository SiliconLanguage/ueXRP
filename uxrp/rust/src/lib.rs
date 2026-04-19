// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// uxrp/rust/src/lib.rs
//
// uXRP eBPF integration library (Aya)
//
// Provides types that mirror the C++ XrpContext structure and a loader that
// uses Aya to attach a compiled eBPF object as a user-space XRP program.

use std::path::Path;

// ---------------------------------------------------------------------------
// XrpContext – must be layout-compatible with the C++ struct in uxrp_engine.hpp
// ---------------------------------------------------------------------------

/// Mirrors uxrp::XrpContext.  Passed to the eBPF program on every NVMe
/// I/O completion; the program may mutate next_lba / next_len to trigger
/// an in-engine resubmission.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XrpContext {
    /// LBA of the completed I/O
    pub lba: u64,
    /// Transfer length in 512-byte blocks
    pub len_blocks: u32,
    /// [out] LBA for resubmission (0 = no resubmit)
    pub next_lba: u64,
    /// [out] Block count for resubmission
    pub next_len: u32,
    /// Pointer to per-request scratch buffer (encoded as u64 for FFI safety)
    pub scratch_ptr: u64,
    /// Scratch buffer size in bytes
    pub scratch_size: u32,
    /// Completion status (0 = success)
    pub status: i32,
}

/// Return value from the eBPF program.
#[repr(i32)]
#[derive(Debug, PartialEq, Eq)]
pub enum XrpVerdict {
    Done     = 0,
    Resubmit = 1,
    Abort    = -1,
}

impl TryFrom<i32> for XrpVerdict {
    type Error = i32;
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            0  => Ok(XrpVerdict::Done),
            1  => Ok(XrpVerdict::Resubmit),
            -1 => Ok(XrpVerdict::Abort),
            x  => Err(x),
        }
    }
}

// ---------------------------------------------------------------------------
// BpfXrpLoader – loads an eBPF object using Aya and exposes a run() method
// ---------------------------------------------------------------------------

/// Wraps an Aya-loaded eBPF program for use with the uXRP engine.
pub struct BpfXrpLoader {
    obj_path:    std::path::PathBuf,
    prog_name:   String,
    /// Placeholder: in a full Aya integration this would hold the loaded
    /// `aya::Ebpf` instance and the pinned program handle.
    _loaded: bool,
}

impl BpfXrpLoader {
    /// Create a new loader.
    ///
    /// # Arguments
    /// * `obj_path`  – path to the compiled eBPF object file (.o)
    /// * `prog_name` – ELF section / program name (e.g. "xrp_prog")
    pub fn new<P: AsRef<Path>>(obj_path: P, prog_name: &str) -> Self {
        BpfXrpLoader {
            obj_path:  obj_path.as_ref().to_path_buf(),
            prog_name: prog_name.to_owned(),
            _loaded:   false,
        }
    }

    /// Load and JIT-compile the eBPF object via Aya.
    ///
    /// In a production build this calls `aya::Ebpf::load_file` and then
    /// retrieves the program from the `programs` map.  The stub below
    /// demonstrates the intended call pattern.
    pub fn load(&mut self) -> anyhow::Result<()> {
        use anyhow::Context as _;

        log::info!(
            "Loading eBPF object '{}' section '{}'",
            self.obj_path.display(),
            self.prog_name
        );

        // Stub: in a live build uncomment the following (requires root /
        // CAP_BPF and a kernel with XRP support):
        //
        // let mut bpf = aya::Ebpf::load_file(&self.obj_path)
        //     .with_context(|| format!("Failed to load {}", self.obj_path.display()))?;
        //
        // let prog: &mut aya::programs::Xdp = bpf
        //     .program_mut(&self.prog_name)
        //     .ok_or_else(|| anyhow::anyhow!("Program '{}' not found", self.prog_name))?
        //     .try_into()?;
        //
        // prog.load().with_context(|| "Failed to load XRP program")?;

        self._loaded = true;
        Ok(())
    }

    /// Execute the eBPF program against an XrpContext (uBPF-style call).
    ///
    /// Returns the XrpVerdict from the program's return value.
    pub fn run(&self, ctx: &mut XrpContext) -> anyhow::Result<XrpVerdict> {
        if !self._loaded {
            anyhow::bail!("BpfXrpLoader::run called before load()");
        }
        // Stub: a real implementation would call the JIT-compiled function
        // pointer obtained from Aya / uBPF here.
        //
        // For now, simulate a Done verdict (no resubmission).
        ctx.next_lba = 0;
        ctx.next_len = 0;
        Ok(XrpVerdict::Done)
    }
}
