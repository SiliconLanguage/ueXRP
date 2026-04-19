// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// xrp_direct/include/xrp_direct.hpp
//
// XRP Direct – top-level public header
//
// Aggregates the BlueField-3 SNAP integration and the DPU-local eBPF
// resubmission pipeline into a single include.

#pragma once

#include "bluefield3_snap.hpp"

#include <cstdint>
#include <string>

namespace xrp_direct {

// ---------------------------------------------------------------------------
// DPU runtime configuration
// ---------------------------------------------------------------------------

struct DpuConfig {
    std::string bpf_obj_path;  ///< eBPF object to load on the DPU
    std::string bpf_section;   ///< ELF section name (e.g. "xrp_prog")
    uint32_t    nsid;          ///< NVMe namespace ID for resubmissions
    bool        mock_mode;     ///< when true, all SNAP calls are simulated
};

// ---------------------------------------------------------------------------
// XRP Direct pipeline
// ---------------------------------------------------------------------------

/// High-level orchestrator: loads the eBPF program, registers the SNAP
/// read handler, and connects the resubmission loop.
class XrpDirectPipeline {
public:
    explicit XrpDirectPipeline(const DpuConfig &cfg);
    ~XrpDirectPipeline();

    /// Load the eBPF program and register it with the SNAP interceptor.
    bool init();

    /// Process one incoming SQE through the full pipeline (useful for
    /// testing and bring-up without a live SNAP environment).
    bool process(const SnapNvmeSqe &sqe, SnapNvmeCqe &cqe_out);

    /// Tear down SNAP registration and unload the BPF program.
    void shutdown();

private:
    DpuConfig cfg_;
    int       bpf_fd_ = -1;
};

} // namespace xrp_direct
