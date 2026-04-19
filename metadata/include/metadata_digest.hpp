// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// metadata/include/metadata_digest.hpp
//
// User-Space Metadata Digest
//
// Holds file-to-LBA mappings extracted via FS_IOC_FIEMAP and exposes
// BPF_disk_trans() – an eBPF helper that translates a logical file offset
// (expressed in 512-byte blocks) into a physical NVMe LBA.

#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>

namespace uxrp::metadata {

// ---------------------------------------------------------------------------
// Extent entry
// ---------------------------------------------------------------------------

/// One contiguous run of logical blocks that maps to a contiguous run of
/// physical blocks on the NVMe device.
struct Extent {
    uint64_t logical_start;  ///< first logical block (512-byte units)
    uint64_t physical_start; ///< corresponding first physical LBA
    uint64_t block_count;    ///< number of 512-byte blocks in this extent
};

// ---------------------------------------------------------------------------
// Shared-memory digest header
// ---------------------------------------------------------------------------

/// Fixed-size header placed at the start of the shared-memory region.
/// Followed immediately in memory by an array of `extent_count` Extent
/// entries.
///
/// Layout (contiguous in shared memory):
///   [ DigestHeader | Extent[0] | Extent[1] | … | Extent[N-1] ]
struct DigestHeader {
    uint32_t          magic;         ///< 0xD1GEST42 – sanity check
    uint32_t          version;       ///< format version (currently 1)
    std::atomic<bool> ready;         ///< true once the writer has committed
    uint32_t          extent_count;  ///< number of valid Extent entries
    uint64_t          total_blocks;  ///< total logical blocks covered
    char              dev_path[64];  ///< null-terminated device path (e.g. /dev/nvme0n1)
    char              file_path[256];///< null-terminated file path
};

static constexpr uint32_t DIGEST_MAGIC   = 0xD16E5742u; // digest header sentinel
static constexpr uint32_t DIGEST_VERSION = 1u;

// ---------------------------------------------------------------------------
// Digest manager
// ---------------------------------------------------------------------------

/// Opens or creates the shared-memory object, populates it by issuing
/// FS_IOC_FIEMAP on the target file, and provides BPF_disk_trans().
class DigestManager {
public:
    /// @param shm_name  POSIX shared-memory name (e.g. "/uxrp_digest")
    /// @param file_path Path to the file whose extents are mapped
    explicit DigestManager(const char *shm_name, const char *file_path);
    ~DigestManager();

    /// (Re-)populate the digest by re-issuing FS_IOC_FIEMAP.
    /// Safe to call while readers hold a stale snapshot: the ready flag
    /// is cleared before the update and set again after.
    bool refresh();

    /// Return a read-only pointer to the header for BPF helper access.
    const DigestHeader *header() const;

    /// Return the extent array that follows the header in shared memory.
    const Extent *extents() const;

private:
    struct Impl;
    Impl *impl_;
};

// ---------------------------------------------------------------------------
// BPF_disk_trans – eBPF helper callable from user-space and from the
//                  eBPF program via a BPF_CALL trampoline.
// ---------------------------------------------------------------------------

/// Translate a logical file block offset into a physical NVMe LBA.
///
/// This function is intentionally written to be inlinable into uBPF JIT
/// output and is also registered as a uBPF helper (helper index 1).
///
/// @param logical_block  Logical block offset within the file (512-byte)
/// @param header         Pointer to the shared DigestHeader
/// @returns              Physical NVMe LBA, or UINT64_MAX on out-of-bounds
///                       (callers must abort the I/O in that case).
[[nodiscard]]
inline uint64_t BPF_disk_trans(uint64_t      logical_block,
                                const DigestHeader *header) noexcept
{
    if (!header || !header->ready.load(std::memory_order_acquire))
        return UINT64_MAX;

    const Extent *ext =
        reinterpret_cast<const Extent *>(
            reinterpret_cast<const char *>(header) + sizeof(DigestHeader));

    for (uint32_t i = 0; i < header->extent_count; ++i) {
        const Extent &e = ext[i];
        if (logical_block >= e.logical_start &&
            logical_block <  e.logical_start + e.block_count) {
            return e.physical_start + (logical_block - e.logical_start);
        }
    }
    // Out-of-bounds: signal abort
    return UINT64_MAX;
}

} // namespace uxrp::metadata
