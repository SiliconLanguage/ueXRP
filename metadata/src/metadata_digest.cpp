// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// metadata/src/metadata_digest.cpp
//
// User-Space Metadata Digest – implementation
//
// Populates a POSIX shared-memory object with file-to-LBA extent mappings
// obtained via FS_IOC_FIEMAP.  The BPF_disk_trans() inline helper in the
// header performs lockless extent lookups at eBPF JIT speed.

#include "metadata_digest.hpp"

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace uxrp::metadata {

// ---------------------------------------------------------------------------
// Pimpl
// ---------------------------------------------------------------------------

struct DigestManager::Impl {
    std::string shm_name;
    std::string file_path;
    int         shm_fd   = -1;
    void       *shm_ptr  = MAP_FAILED;
    size_t      shm_size = 0;

    // Maximum number of extents we support in one mapping
    static constexpr uint32_t MAX_EXTENTS = 8192u;

    static constexpr size_t header_bytes()
    {
        return sizeof(DigestHeader);
    }
    static constexpr size_t total_bytes()
    {
        return sizeof(DigestHeader) + MAX_EXTENTS * sizeof(Extent);
    }
};

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

DigestManager::DigestManager(const char *shm_name, const char *file_path)
    : impl_(new Impl)
{
    impl_->shm_name  = shm_name;
    impl_->file_path = file_path;

    // Open (or create) the shared-memory object
    impl_->shm_fd = shm_open(shm_name,
                             O_RDWR | O_CREAT,
                             S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (impl_->shm_fd < 0)
        throw std::runtime_error(std::string("shm_open: ") + strerror(errno));

    const size_t sz = Impl::total_bytes();
    if (ftruncate(impl_->shm_fd, static_cast<off_t>(sz)) != 0)
        throw std::runtime_error(std::string("ftruncate: ") + strerror(errno));

    impl_->shm_ptr = mmap(nullptr, sz,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED,
                          impl_->shm_fd, 0);
    if (impl_->shm_ptr == MAP_FAILED)
        throw std::runtime_error(std::string("mmap: ") + strerror(errno));

    impl_->shm_size = sz;

    // Initialise the header (idempotent on subsequent opens)
    DigestHeader *hdr = static_cast<DigestHeader *>(impl_->shm_ptr);
    if (hdr->magic != DIGEST_MAGIC) {
        hdr->magic   = DIGEST_MAGIC;
        hdr->version = DIGEST_VERSION;
        hdr->extent_count = 0;
        hdr->total_blocks = 0;
        hdr->ready.store(false, std::memory_order_release);
        std::memset(hdr->dev_path,  0, sizeof(hdr->dev_path));
        std::memset(hdr->file_path, 0, sizeof(hdr->file_path));
        strncpy(hdr->file_path, file_path, sizeof(hdr->file_path) - 1);
    }
}

DigestManager::~DigestManager()
{
    if (impl_->shm_ptr != MAP_FAILED)
        munmap(impl_->shm_ptr, impl_->shm_size);
    if (impl_->shm_fd >= 0)
        close(impl_->shm_fd);
    delete impl_;
}

// ---------------------------------------------------------------------------
// refresh() – re-issue FS_IOC_FIEMAP and rebuild the extent table
// ---------------------------------------------------------------------------

bool DigestManager::refresh()
{
    DigestHeader *hdr = static_cast<DigestHeader *>(impl_->shm_ptr);
    Extent       *ext = reinterpret_cast<Extent *>(hdr + 1);

    // Mark digest as not-ready before we start modifying it
    hdr->ready.store(false, std::memory_order_release);

    int file_fd = open(impl_->file_path.c_str(), O_RDONLY);
    if (file_fd < 0) {
        std::fprintf(stderr, "[metadata] open(%s): %s\n",
                     impl_->file_path.c_str(), strerror(errno));
        return false;
    }

    // Query the file extent map via FS_IOC_FIEMAP
    const uint32_t max_ext = Impl::MAX_EXTENTS;
    const size_t   alloc   = sizeof(fiemap) + max_ext * sizeof(fiemap_extent);
    auto *fm = static_cast<struct fiemap *>(::operator new(alloc));
    std::memset(fm, 0, alloc);
    fm->fm_start          = 0;
    fm->fm_length         = FIEMAP_MAX_OFFSET;
    fm->fm_flags          = FIEMAP_FLAG_SYNC;
    fm->fm_extent_count   = max_ext;

    if (ioctl(file_fd, FS_IOC_FIEMAP, fm) != 0) {
        std::fprintf(stderr, "[metadata] FS_IOC_FIEMAP: %s\n", strerror(errno));
        ::operator delete(fm);
        close(file_fd);
        return false;
    }

    // Populate the shared-memory extent array (512-byte sector units)
    const uint64_t sector_bytes = 512ULL;
    uint64_t total_blocks = 0;
    for (uint32_t i = 0; i < fm->fm_mapped_extents && i < max_ext; ++i) {
        const auto &fe = fm->fm_extents[i];
        ext[i].logical_start  = fe.fe_logical  / sector_bytes;
        ext[i].physical_start = fe.fe_physical / sector_bytes;
        ext[i].block_count    = fe.fe_length   / sector_bytes;
        total_blocks += ext[i].block_count;
    }

    hdr->extent_count = fm->fm_mapped_extents;
    hdr->total_blocks = total_blocks;
    strncpy(hdr->file_path, impl_->file_path.c_str(),
            sizeof(hdr->file_path) - 1);

    ::operator delete(fm);
    close(file_fd);

    // Commit: mark digest as ready
    hdr->ready.store(true, std::memory_order_release);
    return true;
}

const DigestHeader *DigestManager::header() const
{
    return static_cast<const DigestHeader *>(impl_->shm_ptr);
}

const Extent *DigestManager::extents() const
{
    return reinterpret_cast<const Extent *>(
        static_cast<const char *>(impl_->shm_ptr) + sizeof(DigestHeader));
}

} // namespace uxrp::metadata
