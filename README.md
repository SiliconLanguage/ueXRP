# ueXRP
A user-space eBPF storage engine (uXRP) and DPU-offload framework (XRP Direct) extending the Double Trampoline data plane. Integrates uBPF/Aya into lock-free SPDK polling loops for zero-tax NVMe resubmission, bypassing the kernel while maintaining POSIX compatibility via an LD_PRELOAD shim.
