// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// tests/test_metadata.cpp
//
// Unit tests for BPF_disk_trans() and DigestHeader extent lookup.

#include <gtest/gtest.h>
#include "metadata_digest.hpp"

#include <cstring>
#include <memory>
#include <vector>

using namespace uxrp::metadata;

// ---------------------------------------------------------------------------
// Helpers – build an in-memory DigestHeader + Extent array
// ---------------------------------------------------------------------------

struct FakeDigest {
    DigestHeader header;
    Extent       extents[4];

    FakeDigest()
    {
        std::memset(this, 0, sizeof(*this));
        header.magic        = DIGEST_MAGIC;
        header.version      = DIGEST_VERSION;
        header.extent_count = 0;
        header.ready.store(false, std::memory_order_relaxed);
    }

    void add_extent(uint64_t log_start, uint64_t phys_start, uint64_t count)
    {
        uint32_t i = header.extent_count;
        ASSERT_LT(i, 4u);
        extents[i].logical_start  = log_start;
        extents[i].physical_start = phys_start;
        extents[i].block_count    = count;
        ++header.extent_count;
    }

    void commit() { header.ready.store(true, std::memory_order_release); }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(BpfDiskTrans, NullHeaderReturnsMax)
{
    EXPECT_EQ(BPF_disk_trans(0, nullptr), UINT64_MAX);
}

TEST(BpfDiskTrans, NotReadyReturnsMax)
{
    FakeDigest d;
    d.add_extent(0, 1000, 512);
    // ready = false  →  should return UINT64_MAX
    EXPECT_EQ(BPF_disk_trans(0, &d.header), UINT64_MAX);
}

TEST(BpfDiskTrans, SingleExtentHit)
{
    FakeDigest d;
    d.add_extent(/*logical*/ 0, /*physical*/ 2048, /*count*/ 256);
    d.commit();

    // First block
    EXPECT_EQ(BPF_disk_trans(0, &d.header), 2048ULL);
    // Mid block
    EXPECT_EQ(BPF_disk_trans(128, &d.header), 2048ULL + 128ULL);
    // Last block
    EXPECT_EQ(BPF_disk_trans(255, &d.header), 2048ULL + 255ULL);
}

TEST(BpfDiskTrans, SingleExtentMiss)
{
    FakeDigest d;
    d.add_extent(0, 2048, 256);
    d.commit();

    // One past the end
    EXPECT_EQ(BPF_disk_trans(256, &d.header), UINT64_MAX);
}

TEST(BpfDiskTrans, MultipleExtents)
{
    FakeDigest d;
    d.add_extent(  0, 1000, 100);
    d.add_extent(100, 5000, 200);
    d.add_extent(300, 8000,  50);
    d.commit();

    EXPECT_EQ(BPF_disk_trans(  0, &d.header), 1000ULL);
    EXPECT_EQ(BPF_disk_trans( 99, &d.header), 1000ULL + 99ULL);
    EXPECT_EQ(BPF_disk_trans(100, &d.header), 5000ULL);
    EXPECT_EQ(BPF_disk_trans(150, &d.header), 5000ULL + 50ULL);
    EXPECT_EQ(BPF_disk_trans(300, &d.header), 8000ULL);
    EXPECT_EQ(BPF_disk_trans(349, &d.header), 8000ULL + 49ULL);
}

TEST(BpfDiskTrans, GapBetweenExtentsReturnsMax)
{
    FakeDigest d;
    d.add_extent(  0, 1000, 100);
    d.add_extent(200, 5000, 100);
    d.commit();

    // Block 150 falls in the gap between extent 0 and extent 1
    EXPECT_EQ(BPF_disk_trans(150, &d.header), UINT64_MAX);
}

TEST(DigestHeaderConstants, MagicAndVersion)
{
    EXPECT_EQ(DIGEST_MAGIC,   0xD16E5742u);
    EXPECT_EQ(DIGEST_VERSION, 1u);
}
