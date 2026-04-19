// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// xrp_direct/src/xrp_direct.cpp
//
// XRP Direct – mock implementation
//
// Provides a simulation of the BlueField-3 SNAP NVMe interceptor and DPU
// eBPF execution pipeline suitable for functional testing on x86-64 without
// physical BlueField hardware.

#include "xrp_direct.hpp"

#include <cstring>
#include <cstdio>
#include <functional>
#include <stdexcept>

namespace xrp_direct {

// ---------------------------------------------------------------------------
// Module-level SNAP mock state
// ---------------------------------------------------------------------------

static SnapReadHandler g_read_handler;
static int             g_bpf_fd_counter = 0; // mock fd allocator

static constexpr int MAX_RESUBMIT_ITERATIONS = 32;

// ---------------------------------------------------------------------------
// SNAP NVMe interceptor – mock implementation
// ---------------------------------------------------------------------------

void snap_register_read_handler(SnapReadHandler handler)
{
    g_read_handler = std::move(handler);
}

bool snap_process_sqe(const SnapNvmeSqe &sqe, SnapNvmeCqe &cqe_out)
{
    if (!g_read_handler) {
        // No handler: complete with success, no data movement
        std::memset(&cqe_out, 0, sizeof(cqe_out));
        cqe_out.cid    = sqe.cid;
        cqe_out.status = 0x0001; // successful completion, phase = 1
        return false;
    }

    DpuXrpContext ctx {};
    ctx.lba        = sqe.slba;
    ctx.len_blocks = sqe.nlb + 1u; // NVMe nlb is 0-based
    ctx.next_lba   = 0;
    ctx.next_len   = 0;
    ctx.dma_buf    = nullptr;
    ctx.status     = 0;

    bool consumed = g_read_handler(sqe, ctx, cqe_out);

    cqe_out.cid    = sqe.cid;
    cqe_out.status = (ctx.status == 0) ? 0x0001u : 0x0003u;
    return consumed;
}

// ---------------------------------------------------------------------------
// DPU eBPF loader / runner – mock implementation
// ---------------------------------------------------------------------------

int snap_load_bpf_prog(const char *obj_path, const char *section)
{
    if (!obj_path || !section) {
        std::fprintf(stderr, "[xrp_direct] snap_load_bpf_prog: null argument\n");
        return -1;
    }
    std::printf("[xrp_direct] (mock) loaded BPF prog '%s' from '%s', fd=%d\n",
                section, obj_path, g_bpf_fd_counter + 1);
    return ++g_bpf_fd_counter;
}

int snap_run_bpf_prog(int bpf_fd, DpuXrpContext &ctx)
{
    if (bpf_fd <= 0) return -1;
    // Mock: signal Resubmit if next_lba was set by the handler, else Done
    if (ctx.next_lba != 0)
        return 1; // XrpVerdict::Resubmit
    return 0;     // XrpVerdict::Done
}

// ---------------------------------------------------------------------------
// DPU NVMe resubmission – mock implementation
// ---------------------------------------------------------------------------

int snap_nvme_resubmit_read(uint32_t nsid,
                             uint64_t lba,
                             uint32_t lba_count,
                             void    *dma_buf)
{
    (void)dma_buf;
    std::printf("[xrp_direct] (mock) resubmit: nsid=%u lba=%llu count=%u\n",
                nsid, (unsigned long long)lba, lba_count);
    return 0;
}

// ---------------------------------------------------------------------------
// XrpDirectPipeline
// ---------------------------------------------------------------------------

XrpDirectPipeline::XrpDirectPipeline(const DpuConfig &cfg) : cfg_(cfg) {}

XrpDirectPipeline::~XrpDirectPipeline()
{
    shutdown();
}

bool XrpDirectPipeline::init()
{
    bpf_fd_ = snap_load_bpf_prog(cfg_.bpf_obj_path.c_str(),
                                  cfg_.bpf_section.c_str());
    if (bpf_fd_ < 0)
        return false;

    // Register the SNAP read handler as a lambda that drives the eBPF loop
    const uint32_t nsid = cfg_.nsid;
    const int      fd   = bpf_fd_;

    snap_register_read_handler(
        [nsid, fd](const SnapNvmeSqe &sqe,
                   DpuXrpContext      &ctx,
                   SnapNvmeCqe       &cqe_out) -> bool {
            (void)sqe; (void)cqe_out;
            // Drive the eBPF resubmission loop (bounded to MAX_RESUBMIT_ITERATIONS)
            for (int iter = 0; iter < MAX_RESUBMIT_ITERATIONS; ++iter) {
                int verdict = snap_run_bpf_prog(fd, ctx);
                if (verdict == 1 && ctx.next_lba != 0) {
                    snap_nvme_resubmit_read(nsid,
                                            ctx.next_lba, ctx.next_len,
                                            ctx.dma_buf);
                    ctx.lba        = ctx.next_lba;
                    ctx.len_blocks = ctx.next_len;
                    ctx.next_lba   = 0;
                    ctx.next_len   = 0;
                } else {
                    break;
                }
            }
            return true; // command consumed by DPU
        });

    return true;
}

bool XrpDirectPipeline::process(const SnapNvmeSqe &sqe, SnapNvmeCqe &cqe_out)
{
    return snap_process_sqe(sqe, cqe_out);
}

void XrpDirectPipeline::shutdown()
{
    g_read_handler = nullptr;
    bpf_fd_ = -1;
}

} // namespace xrp_direct
