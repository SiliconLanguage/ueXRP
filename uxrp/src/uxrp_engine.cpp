// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// uxrp/src/uxrp_engine.cpp
//
// uXRP Execution Environment – implementation
//
// Lock-free SPDK NVMe polling loop that integrates a user-space eBPF VM
// (uBPF).  On each completion the CQE is translated into an XrpContext and
// handed to the JIT-compiled eBPF program.  If the program signals
// XrpVerdict::Resubmit the engine re-issues the read via resubmit_read()
// without ever touching the kernel syscall path.

#include "uxrp_engine.hpp"

// SPDK headers (available when building against an SPDK installation)
#include <spdk/nvme.h>
#include <spdk/env.h>
#include <spdk/log.h>

// uBPF – user-space eBPF VM / JIT compiler
#include <ubpf.h>

#include <cstring>
#include <cassert>
#include <atomic>
#include <stdexcept>

namespace uxrp {

// ---------------------------------------------------------------------------
// Per-request callback context
// ---------------------------------------------------------------------------

struct ReqCtx {
    Engine::Impl    *engine;
    uint64_t         lba;
    uint32_t         len_blocks;
    void            *buf;
    void            *caller_cb_arg;
    uint8_t          scratch[512]; ///< per-request scratch buffer for BPF
};

// ---------------------------------------------------------------------------
// Pimpl
// ---------------------------------------------------------------------------

struct Engine::Impl {
    EngineConfig             cfg;
    struct spdk_nvme_ctrlr  *ctrlr   = nullptr;
    struct spdk_nvme_ns     *ns      = nullptr;
    struct spdk_nvme_qpair  *qpair   = nullptr;
    struct ubpf_vm          *vm      = nullptr;
    ubpf_jit_fn              jit_fn  = nullptr;
    std::atomic<bool>        running {false};

    explicit Impl(const EngineConfig &c) : cfg(c) {}
};

// ---------------------------------------------------------------------------
// SPDK probe callbacks
// ---------------------------------------------------------------------------

static bool probe_cb(void *cb_ctx,
                     const struct spdk_nvme_transport_id *trid,
                     struct spdk_nvme_ctrlr_opts *opts)
{
    (void)cb_ctx; (void)opts;
    SPDK_NOTICELOG("Attaching to NVMe controller: %s\n", trid->traddr);
    return true;
}

static void attach_cb(void *cb_ctx,
                      const struct spdk_nvme_transport_id *trid,
                      struct spdk_nvme_ctrlr *ctrlr,
                      const struct spdk_nvme_ctrlr_opts *opts)
{
    (void)trid; (void)opts;
    Engine::Impl *impl = static_cast<Engine::Impl *>(cb_ctx);
    if (!impl->ctrlr) {
        impl->ctrlr = ctrlr;
        impl->ns    = spdk_nvme_ctrlr_get_ns(ctrlr, 1); // namespace 1
    }
}

// ---------------------------------------------------------------------------
// NVMe completion handler
// ---------------------------------------------------------------------------

static void io_complete_cb(void *cb_arg, const struct spdk_nvme_cpl *cpl)
{
    ReqCtx      *req  = static_cast<ReqCtx *>(cb_arg);
    Engine::Impl *impl = req->engine;

    // Build XrpContext from the CQE
    XrpContext ctx {};
    ctx.lba          = req->lba;
    ctx.len_blocks   = req->len_blocks;
    ctx.next_lba     = 0;
    ctx.next_len     = 0;
    ctx.scratch      = req->scratch;
    ctx.scratch_size = sizeof(req->scratch);
    ctx.status       = spdk_nvme_cpl_is_error(cpl) ? -1 : 0;

    // Run the JIT-compiled eBPF program
    XrpVerdict verdict = XrpVerdict::Done;
    if (impl->jit_fn) {
        uint64_t bpf_ret = impl->jit_fn(&ctx, sizeof(ctx));
        verdict = static_cast<XrpVerdict>(
            ctx.status < 0 ? -1 : static_cast<int>(bpf_ret));
    }

    if (verdict == XrpVerdict::Resubmit && ctx.next_lba != 0) {
        int rc = resubmit_read(impl->ns, impl->qpair,
                               req->buf, ctx.next_lba, ctx.next_len,
                               cb_arg);
        if (rc == 0)
            return; // ownership transferred to the new request
        SPDK_ERRLOG("resubmit_read failed: %d\n", rc);
    }

    // Release request context
    delete req;
}

// ---------------------------------------------------------------------------
// Engine implementation
// ---------------------------------------------------------------------------

Engine::Engine(const EngineConfig &cfg) : impl_(new Impl(cfg)) {}

Engine::~Engine()
{
    stop();
    if (impl_->vm)
        ubpf_destroy(impl_->vm);
    if (impl_->ctrlr)
        spdk_nvme_detach(impl_->ctrlr);
    delete impl_;
}

bool Engine::load_bpf()
{
    impl_->vm = ubpf_create();
    if (!impl_->vm)
        return false;

    // Read the compiled eBPF object file
    FILE *f = fopen(impl_->cfg.bpf_obj_path, "rb");
    if (!f) {
        SPDK_ERRLOG("Cannot open BPF object: %s\n", impl_->cfg.bpf_obj_path);
        return false;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    auto *buf = new uint8_t[sz];
    fread(buf, 1, sz, f);
    fclose(f);

    char *errmsg = nullptr;
    int rc = ubpf_load_elf(impl_->vm, buf, static_cast<size_t>(sz), &errmsg);
    delete[] buf;
    if (rc != 0) {
        SPDK_ERRLOG("ubpf_load_elf: %s\n", errmsg ? errmsg : "unknown");
        free(errmsg);
        return false;
    }

    impl_->jit_fn = ubpf_compile(impl_->vm, &errmsg);
    if (!impl_->jit_fn) {
        SPDK_ERRLOG("ubpf_compile: %s\n", errmsg ? errmsg : "unknown");
        free(errmsg);
        return false;
    }
    return true;
}

void Engine::start()
{
    // Initialise SPDK environment
    struct spdk_env_opts env_opts;
    spdk_env_opts_init(&env_opts);
    env_opts.name = "uxrp_engine";
    if (spdk_env_init(&env_opts) < 0)
        throw std::runtime_error("spdk_env_init failed");

    // Probe and attach to the NVMe controller
    struct spdk_nvme_transport_id trid;
    spdk_nvme_trid_populate_transport(&trid, SPDK_NVME_TRANSPORT_PCIE);
    snprintf(trid.traddr, sizeof(trid.traddr), "%s", impl_->cfg.trid);

    if (spdk_nvme_probe(&trid, impl_, probe_cb, attach_cb, nullptr) != 0)
        throw std::runtime_error("spdk_nvme_probe failed");

    if (!impl_->ctrlr || !impl_->ns)
        throw std::runtime_error("No NVMe namespace found");

    struct spdk_nvme_io_qpair_opts qopts;
    spdk_nvme_ctrlr_get_default_io_qpair_opts(impl_->ctrlr, &qopts,
                                              sizeof(qopts));
    qopts.qprio = SPDK_NVME_QPRIO_URGENT;

    impl_->qpair = spdk_nvme_ctrlr_alloc_io_qpair(impl_->ctrlr, &qopts,
                                                   sizeof(qopts));
    if (!impl_->qpair)
        throw std::runtime_error("Failed to allocate NVMe qpair");

    impl_->running.store(true, std::memory_order_release);

    // Lock-free polling loop
    while (impl_->running.load(std::memory_order_acquire)) {
        int processed = spdk_nvme_qpair_process_completions(impl_->qpair, 0);
        (void)processed;
        // poll_timeout_us == 0 means spin; otherwise yield if idle
        if (impl_->cfg.poll_timeout_us > 0 && processed == 0)
            spdk_delay_us(impl_->cfg.poll_timeout_us);
    }

    // Drain any in-flight completions before returning
    spdk_nvme_qpair_process_completions(impl_->qpair, 0);
    spdk_nvme_ctrlr_free_io_qpair(impl_->qpair);
    impl_->qpair = nullptr;
}

void Engine::stop()
{
    impl_->running.store(false, std::memory_order_release);
}

int Engine::submit_read(uint64_t lba, uint32_t len_blocks, void *buf,
                        void *cb_arg)
{
    if (!impl_->qpair || !impl_->ns)
        return -EINVAL;

    auto *req = new ReqCtx{};
    req->engine       = impl_;
    req->lba          = lba;
    req->len_blocks   = len_blocks;
    req->buf          = buf;
    req->caller_cb_arg = cb_arg;
    std::memset(req->scratch, 0, sizeof(req->scratch));

    return spdk_nvme_ns_cmd_read(impl_->ns, impl_->qpair,
                                 buf, lba, len_blocks,
                                 io_complete_cb, req, 0);
}

// ---------------------------------------------------------------------------
// Resubmit helper
// ---------------------------------------------------------------------------

int resubmit_read(spdk_nvme_ns    *ns,
                  spdk_nvme_qpair *qpair,
                  void            *buf,
                  uint64_t         lba,
                  uint32_t         lba_count,
                  void            *cb_arg)
{
    // Reuse the existing callback context – the ReqCtx fields are updated
    // so the next completion still routes through io_complete_cb.
    ReqCtx *req = static_cast<ReqCtx *>(cb_arg);
    req->lba        = lba;
    req->len_blocks = lba_count;
    std::memset(req->scratch, 0, sizeof(req->scratch));

    return spdk_nvme_ns_cmd_read(ns, qpair,
                                 buf, lba, lba_count,
                                 io_complete_cb, req, 0);
}

} // namespace uxrp
