// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// xrp_direct/include/bluefield3_snap.hpp
//
// XRP Direct – NVIDIA BlueField-3 SNAP integration mock headers
//
// Provides a structural outline for intercepting NVMe commands on the
// BlueField-3 DPU ARM cores and executing the eBPF resubmission loop
// locally, eliminating any host-side NVMe round-trip for re-mapped I/Os.

#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>

namespace xrp_direct {

// ---------------------------------------------------------------------------
// SNAP NVMe command representation (mock)
// ---------------------------------------------------------------------------

/// Subset of the NVMe submission queue entry relevant to Read commands.
/// In a real SNAP integration this would come from the snap_nvme_sq_entry
/// provided by the BlueField NVMe emulation layer.
struct SnapNvmeSqe {
    uint8_t  opc;        ///< opcode (0x02 = Read)
    uint16_t cid;        ///< command identifier
    uint64_t slba;       ///< starting LBA
    uint16_t nlb;        ///< number of logical blocks (0-based)
    uint32_t nsid;       ///< namespace identifier
};

/// NVMe completion queue entry returned to the host.
struct SnapNvmeCqe {
    uint32_t dw0;        ///< command-specific
    uint32_t dw1;        ///< reserved
    uint16_t sq_head;    ///< submission queue head pointer
    uint16_t sq_id;      ///< submission queue identifier
    uint16_t cid;        ///< command identifier
    uint16_t status;     ///< status field (bits 15:1) + phase (bit 0)
};

// ---------------------------------------------------------------------------
// DPU eBPF execution context
// ---------------------------------------------------------------------------

/// Context passed into the eBPF resubmission program running on the ARM
/// cores of the BlueField-3.  Mirrors XrpContext from uxrp_engine.hpp so
/// the same compiled eBPF object can run in both environments.
struct DpuXrpContext {
    uint64_t lba;
    uint32_t len_blocks;
    uint64_t next_lba;     ///< [out] resubmit target
    uint32_t next_len;     ///< [out] resubmit length
    void    *dma_buf;      ///< DPU-side DMA-coherent buffer
    uint32_t dma_buf_size;
    int      status;
};

// ---------------------------------------------------------------------------
// SNAP NVMe interceptor
// ---------------------------------------------------------------------------

/// Callback signature invoked for every intercepted Read SQE.
/// Return true to consume the command locally (resubmit via DPU NVMe path);
/// return false to forward to the host unchanged.
using SnapReadHandler = std::function<bool(const SnapNvmeSqe &sqe,
                                           DpuXrpContext      &ctx,
                                           SnapNvmeCqe        &cqe_out)>;

/// Registers a Read-command interceptor with the SNAP emulation layer.
/// In production this calls snap_nvme_ctrl_set_io_handler(); the mock
/// implementation stores the callback and invokes it in process_sqe().
void snap_register_read_handler(SnapReadHandler handler);

/// Simulates receiving an SQE from the host (test / bring-up helper).
/// Invokes the registered handler, then fills cqe_out.
bool snap_process_sqe(const SnapNvmeSqe &sqe, SnapNvmeCqe &cqe_out);

// ---------------------------------------------------------------------------
// DPU eBPF loader
// ---------------------------------------------------------------------------

/// Load an eBPF object file onto the DPU ARM cores via the SNAP BPF
/// subsystem.  Returns a non-negative program fd on success, -1 on error.
int snap_load_bpf_prog(const char *obj_path, const char *section);

/// Execute an already-loaded BPF program against a DpuXrpContext.
/// Returns the XrpVerdict integer (0=Done, 1=Resubmit, -1=Abort).
int snap_run_bpf_prog(int bpf_fd, DpuXrpContext &ctx);

// ---------------------------------------------------------------------------
// DPU NVMe resubmission
// ---------------------------------------------------------------------------

/// Issue a new NVMe Read command directly from the DPU ARM core to the
/// backing NVMe device, bypassing the PCIe host path entirely.
///
/// @param nsid       NVMe namespace identifier
/// @param lba        Starting LBA
/// @param lba_count  Number of logical blocks
/// @param dma_buf    DPU DMA-coherent buffer (allocated via snap_dma_buf_alloc)
/// @returns 0 on success, -errno on failure
int snap_nvme_resubmit_read(uint32_t nsid,
                             uint64_t lba,
                             uint32_t lba_count,
                             void    *dma_buf);

} // namespace xrp_direct
