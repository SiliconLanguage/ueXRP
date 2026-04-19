// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// trampoline/src/trampoline_shim.c
//
// Trampoline Shim – LD_PRELOAD implementation
//
// Intercepts pread64 / pwrite64 and submits I/O requests to the shared-
// memory IOR ring consumed by the uXRP engine.  The shim spins on the result
// slot to preserve the synchronous POSIX contract for the caller.

#define _GNU_SOURCE
#include "trampoline_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>

// ---------------------------------------------------------------------------
// Originals resolved via dlsym(RTLD_NEXT, ...)
// ---------------------------------------------------------------------------

typedef ssize_t (*pread64_fn)(int, void *, size_t, off_t);
typedef ssize_t (*pwrite64_fn)(int, const void *, size_t, off_t);

static pread64_fn  real_pread64  = NULL;
static pwrite64_fn real_pwrite64 = NULL;

// ---------------------------------------------------------------------------
// Shared-memory IOR ring state
// ---------------------------------------------------------------------------

static IorHeader *g_ior_hdr   = NULL;
static IorSlot   *g_ior_slots = NULL;
static int        g_shm_fd    = -1;
static size_t     g_shm_size  = 0;

#define IOR_MAGIC_VAL 0x10714247u  /* matches IOR_MAGIC in the header */

static inline uint32_t ior_mask(void)
{
    return g_ior_hdr->capacity - 1;
}

// ---------------------------------------------------------------------------
// Ring submission – lock-free SPSC enqueue
// ---------------------------------------------------------------------------

/// Submit one I/O operation to the ring.
/// Spins until a slot is available (back-pressure).
/// @returns pointer to the claimed slot (seq is odd = in-flight).
static IorSlot *ior_submit(IorOpType op, int fd, uint64_t offset,
                            uint32_t len, void *buf, void *cookie)
{
    uint64_t head = atomic_load_explicit(&g_ior_hdr->head,
                                         memory_order_relaxed);
    for (;;) {
        uint32_t idx = (uint32_t)(head & ior_mask());
        IorSlot *slot = &g_ior_slots[idx];
        uint32_t seq  = atomic_load_explicit(&slot->seq,
                                             memory_order_acquire);
        // Even seq at position head means slot is free
        if (seq == (uint32_t)(head & 0xFFFFFFFFu)) {
            if (atomic_compare_exchange_weak_explicit(
                    &g_ior_hdr->head,
                    &head, head + 1,
                    memory_order_relaxed,
                    memory_order_relaxed)) {
                slot->op     = (uint32_t)op;
                slot->fd     = fd;
                slot->offset = offset;
                slot->len    = len;
                slot->buf    = buf;
                slot->cookie = cookie;
                slot->result = 0;
                // Publish: set seq to odd to signal consumer
                atomic_store_explicit(&slot->seq,
                                      (uint32_t)((head & 0xFFFFFFFFu) + 1),
                                      memory_order_release);
                return slot;
            }
        } else {
            // Ring full – spin with a short back-off
            head = atomic_load_explicit(&g_ior_hdr->head,
                                         memory_order_relaxed);
            struct timespec ts = {0, 100};
            nanosleep(&ts, NULL);
        }
    }
}

// ---------------------------------------------------------------------------
// Wait for the engine to post a result into a slot
// ---------------------------------------------------------------------------

static int ior_wait(IorSlot *slot)
{
    // The uXRP engine clears the odd-seq bit (sets seq to head+1 which is
    // even again) and writes slot->result when it is done.
    uint32_t expected_done = atomic_load_explicit(&slot->seq,
                                                   memory_order_relaxed) + 1;
    for (;;) {
        uint32_t s = atomic_load_explicit(&slot->seq, memory_order_acquire);
        if (s == expected_done)
            break;
        struct timespec ts = {0, 200};
        nanosleep(&ts, NULL);
    }
    return slot->result;
}

// ---------------------------------------------------------------------------
// Shim initialisation (constructor)
// ---------------------------------------------------------------------------

__attribute__((constructor))
void uxrp_shim_init(void)
{
    real_pread64  = (pread64_fn)  dlsym(RTLD_NEXT, "pread64");
    real_pwrite64 = (pwrite64_fn) dlsym(RTLD_NEXT, "pwrite64");

    if (!real_pread64 || !real_pwrite64) {
        fprintf(stderr, "[trampoline] dlsym failed: %s\n", dlerror());
        return;
    }

    const char *shm_name = getenv("UXRP_IOR_SHM");
    if (!shm_name)
        shm_name = "/uxrp_ior";

    const char *cap_str = getenv("UXRP_IOR_CAPACITY");
    uint32_t capacity = cap_str ? (uint32_t)atoi(cap_str) : IOR_DEFAULT_CAPACITY;
    // Enforce power-of-two
    if (capacity == 0 || (capacity & (capacity - 1)) != 0)
        capacity = IOR_DEFAULT_CAPACITY;

    const size_t slots_bytes = capacity * sizeof(IorSlot);
    g_shm_size = sizeof(IorHeader) + slots_bytes;

    g_shm_fd = shm_open(shm_name, O_RDWR | O_CREAT,
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (g_shm_fd < 0) {
        fprintf(stderr, "[trampoline] shm_open(%s): %s\n",
                shm_name, strerror(errno));
        return;
    }

    if (ftruncate(g_shm_fd, (off_t)g_shm_size) != 0) {
        fprintf(stderr, "[trampoline] ftruncate: %s\n", strerror(errno));
        return;
    }

    void *ptr = mmap(NULL, g_shm_size,
                     PROT_READ | PROT_WRITE, MAP_SHARED,
                     g_shm_fd, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "[trampoline] mmap: %s\n", strerror(errno));
        return;
    }

    g_ior_hdr   = (IorHeader *)ptr;
    g_ior_slots = (IorSlot   *)((char *)ptr + sizeof(IorHeader));

    // Initialise ring header (idempotent if engine already wrote it)
    if (g_ior_hdr->magic != IOR_MAGIC_VAL) {
        memset(g_ior_hdr, 0, sizeof(IorHeader));
        g_ior_hdr->magic    = IOR_MAGIC_VAL;
        g_ior_hdr->capacity = capacity;
        atomic_store(&g_ior_hdr->head, 0);
        atomic_store(&g_ior_hdr->tail, 0);
        memset(g_ior_slots, 0, slots_bytes);
    }
}

// ---------------------------------------------------------------------------
// Shim teardown (destructor)
// ---------------------------------------------------------------------------

__attribute__((destructor))
void uxrp_shim_fini(void)
{
    if (g_ior_hdr != NULL) {
        munmap(g_ior_hdr, g_shm_size);
        g_ior_hdr   = NULL;
        g_ior_slots = NULL;
    }
    if (g_shm_fd >= 0) {
        close(g_shm_fd);
        g_shm_fd = -1;
    }
}

// ---------------------------------------------------------------------------
// Intercepted pread64
// ---------------------------------------------------------------------------

ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
{
    if (!g_ior_hdr || !real_pread64) {
        // Ring not available – fall through to the real syscall
        if (real_pread64)
            return real_pread64(fd, buf, count, offset);
        errno = ENOSYS;
        return -1;
    }

    IorSlot *slot = ior_submit(IOR_OP_READ, fd,
                                (uint64_t)offset, (uint32_t)count,
                                buf, NULL);
    int result = ior_wait(slot);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (ssize_t)result;
}

// ---------------------------------------------------------------------------
// Intercepted pwrite64
// ---------------------------------------------------------------------------

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)
{
    if (!g_ior_hdr || !real_pwrite64) {
        if (real_pwrite64)
            return real_pwrite64(fd, buf, count, offset);
        errno = ENOSYS;
        return -1;
    }

    IorSlot *slot = ior_submit(IOR_OP_WRITE, fd,
                                (uint64_t)offset, (uint32_t)count,
                                (void *)buf, NULL);
    int result = ior_wait(slot);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (ssize_t)result;
}
