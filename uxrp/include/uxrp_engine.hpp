// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// uxrp/include/uxrp_engine.hpp
//
// uXRP Execution Environment – public API
//
// Integrates a lock-free SPDK NVMe polling loop with a user-space eBPF
// virtual machine (uBPF / Aya).  Each completion drives a
// BPF_PROG_TYPE_XRP-compatible eBPF program whose resubmission decisions
// are fed back into spdk_nvme_ns_cmd_read without re-entering the kernel.

#pragma once

#include <cstdint>
#include <atomic>

// Forward declarations for SPDK types so consumers do not need the full
// SPDK headers unless they are compiling the engine translation unit.
struct spdk_nvme_ns;
struct spdk_nvme_qpair;
struct spdk_nvme_cpl;

namespace uxrp {

// ---------------------------------------------------------------------------
// BPF_PROG_TYPE_XRP – function signature mirrored in user-space
// ---------------------------------------------------------------------------

/// Mirrors the kernel-side XRP context passed to the eBPF program on every
/// I/O completion.  The program may mutate next_lba / next_len to trigger
/// an in-engine resubmission without any syscall.
struct XrpContext {
    uint64_t lba;          ///< LBA of the completed I/O
    uint32_t len_blocks;   ///< transfer length in 512-byte blocks
    uint64_t next_lba;     ///< [out] LBA for resubmission (0 = no resubmit)
    uint32_t next_len;     ///< [out] block count for resubmission
    void    *scratch;      ///< pointer to per-request scratch buffer
    uint32_t scratch_size; ///< scratch buffer size in bytes
    int      status;       ///< completion status (0 = success)
};

/// Return value expected from the eBPF program.
enum class XrpVerdict : int {
    Done     = 0,  ///< I/O chain is complete
    Resubmit = 1,  ///< engine should issue another read with next_lba/next_len
    Abort    = -1, ///< fatal error – release all resources
};

// ---------------------------------------------------------------------------
// Engine configuration
// ---------------------------------------------------------------------------

struct EngineConfig {
    const char *trtype;          ///< transport type, e.g. "PCIe"
    const char *trid;            ///< transport ID string (BDF or NQN)
    uint32_t    queue_depth;     ///< maximum outstanding I/Os per qpair
    uint32_t    poll_timeout_us; ///< µs budget per poll() call (0 = spin)
    const char *bpf_obj_path;    ///< path to compiled eBPF object file
    const char *bpf_prog_name;   ///< ELF section name of the XRP program
};

// ---------------------------------------------------------------------------
// Engine lifecycle
// ---------------------------------------------------------------------------

class Engine {
public:
    explicit Engine(const EngineConfig &cfg);
    ~Engine();

    /// Load and JIT-compile the eBPF object.  Must be called once before
    /// start().
    bool load_bpf();

    /// Allocate an SPDK NVMe qpair and enter the polling loop.  This call
    /// blocks the calling thread; run it on a dedicated reactor core.
    void start();

    /// Signal the polling loop to drain and exit gracefully.
    void stop();

    /// Submit a single read request.  Thread-safe when serialised via the
    /// Trampoline Shim ring buffer.
    int submit_read(uint64_t lba, uint32_t len_blocks, void *buf,
                    void *cb_arg);

private:
    struct Impl;
    Impl *impl_;
};

// ---------------------------------------------------------------------------
// Resubmit helper – wraps spdk_nvme_ns_cmd_read
// ---------------------------------------------------------------------------

/// Issued by the completion handler when the eBPF program sets
/// XrpVerdict::Resubmit.  Avoids re-entering the kernel by reusing the
/// existing qpair directly.
///
/// @returns 0 on success, negative SPDK errno on failure.
int resubmit_read(spdk_nvme_ns    *ns,
                  spdk_nvme_qpair *qpair,
                  void            *buf,
                  uint64_t         lba,
                  uint32_t         lba_count,
                  void            *cb_arg);

} // namespace uxrp
