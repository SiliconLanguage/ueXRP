// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// tests/test_xrp_direct.cpp
//
// Unit tests for the XRP Direct mock pipeline (BlueField-3 SNAP simulation).

#include <gtest/gtest.h>
#include "xrp_direct.hpp"

using namespace xrp_direct;

// ---------------------------------------------------------------------------
// snap_process_sqe without a registered handler
// ---------------------------------------------------------------------------

TEST(SnapMock, NoHandlerCompletesSuccessfully)
{
    SnapNvmeSqe sqe {};
    sqe.opc  = 0x02; // Read
    sqe.cid  = 42;
    sqe.slba = 1024;
    sqe.nlb  = 7;  // 8 blocks
    sqe.nsid = 1;

    SnapNvmeCqe cqe {};
    bool consumed = snap_process_sqe(sqe, cqe);

    EXPECT_FALSE(consumed);
    EXPECT_EQ(cqe.cid,    42u);
    EXPECT_EQ(cqe.status, 0x0001u); // successful + phase bit
}

// ---------------------------------------------------------------------------
// XrpDirectPipeline init + process (mock mode, no real BPF file needed)
// ---------------------------------------------------------------------------

TEST(XrpDirectPipeline, InitAndProcess)
{
    DpuConfig cfg;
    cfg.bpf_obj_path = "dummy.o";
    cfg.bpf_section  = "xrp_prog";
    cfg.nsid         = 1;
    cfg.mock_mode    = true;

    XrpDirectPipeline pipeline(cfg);
    ASSERT_TRUE(pipeline.init());

    SnapNvmeSqe sqe {};
    sqe.opc  = 0x02;
    sqe.cid  = 7;
    sqe.slba = 512;
    sqe.nlb  = 15; // 16 blocks
    sqe.nsid = 1;

    SnapNvmeCqe cqe {};
    bool consumed = pipeline.process(sqe, cqe);

    // Handler was registered → consumed = true
    EXPECT_TRUE(consumed);
    EXPECT_EQ(cqe.cid, 7u);
}

// ---------------------------------------------------------------------------
// snap_run_bpf_prog verdict mapping
// ---------------------------------------------------------------------------

TEST(SnapBpfProg, InvalidFdReturnsError)
{
    DpuXrpContext ctx {};
    EXPECT_EQ(snap_run_bpf_prog(-1, ctx), -1);
    EXPECT_EQ(snap_run_bpf_prog(0,  ctx), -1);
}

TEST(SnapBpfProg, DoneWhenNextLbaZero)
{
    // Load a mock program to get a valid fd
    int fd = snap_load_bpf_prog("dummy.o", "xrp_prog");
    ASSERT_GT(fd, 0);

    DpuXrpContext ctx {};
    ctx.next_lba = 0;
    EXPECT_EQ(snap_run_bpf_prog(fd, ctx), 0); // Done
}

TEST(SnapBpfProg, ResubmitWhenNextLbaSet)
{
    int fd = snap_load_bpf_prog("dummy.o", "xrp_prog");
    ASSERT_GT(fd, 0);

    DpuXrpContext ctx {};
    ctx.next_lba = 2048;
    ctx.next_len = 8;
    EXPECT_EQ(snap_run_bpf_prog(fd, ctx), 1); // Resubmit
}

// ---------------------------------------------------------------------------
// snap_nvme_resubmit_read – smoke test (mock always returns 0)
// ---------------------------------------------------------------------------

TEST(SnapNvme, ResubmitReadReturnSuccess)
{
    EXPECT_EQ(snap_nvme_resubmit_read(1, 4096, 8, nullptr), 0);
}
