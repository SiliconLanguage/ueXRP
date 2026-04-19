// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// trampoline/include/trampoline_shim.h
//
// Trampoline Shim – public C interface
//
// LD_PRELOAD library that intercepts synchronous POSIX I/O (pread64,
// pwrite64) and translates them into asynchronous, lock-free submissions
// to the shared-memory ring buffer (IOR) consumed by the uXRP engine.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <sys/types.h>

// ---------------------------------------------------------------------------
// IOR – shared-memory I/O Ring
// ---------------------------------------------------------------------------

/// Operation type stored in each ring slot.
typedef enum {
    IOR_OP_READ  = 0,
    IOR_OP_WRITE = 1,
} IorOpType;

/// One slot in the lock-free single-producer / single-consumer ring.
/// Sized to fit inside one cache line (64 bytes) so writes are atomic on
/// x86-64 / ARM64.
typedef struct __attribute__((aligned(64))) {
    _Atomic uint32_t seq;      ///< sequence counter – even = empty, odd = full
    uint32_t         op;       ///< IorOpType
    int              fd;       ///< original file descriptor
    uint64_t         offset;   ///< file offset in bytes
    uint32_t         len;      ///< transfer length in bytes
    void            *buf;      ///< data buffer (caller-owned)
    void            *cookie;   ///< opaque completion cookie
    int              result;   ///< [out] bytes transferred or -errno
} IorSlot;

/// Ring header placed at the start of the shared-memory object.
/// Followed immediately by IorSlot[capacity] in the same mapping.
typedef struct {
    uint32_t         magic;    ///< 0x10R1NG42
    uint32_t         capacity; ///< number of slots (must be a power of 2)
    _Atomic uint64_t head;     ///< producer write index
    _Atomic uint64_t tail;     ///< consumer read  index
} IorHeader;

#define IOR_MAGIC     0x10714247u  /* ring identifier */
#define IOR_DEFAULT_CAPACITY 4096u

// ---------------------------------------------------------------------------
// Shim initialisation / teardown
// ---------------------------------------------------------------------------

/// Called automatically via __attribute__((constructor)) when the shim is
/// LD_PRELOADed.  Attaches to (or creates) the shared-memory ring at the
/// path given by the environment variable UXRP_IOR_SHM (default:
/// "/uxrp_ior").
void uxrp_shim_init(void);

/// Drains the ring and detaches from shared memory.
void uxrp_shim_fini(void);

// ---------------------------------------------------------------------------
// Intercepted POSIX calls
// ---------------------------------------------------------------------------

/// Asynchronous-under-the-hood replacement for pread64(2).
/// Submits the request to the IOR ring and blocks until the uXRP engine
/// posts a result, preserving the synchronous caller contract.
ssize_t pread64(int fd, void *buf, size_t count, off_t offset);

/// Asynchronous-under-the-hood replacement for pwrite64(2).
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset);

#ifdef __cplusplus
} // extern "C"
#endif
