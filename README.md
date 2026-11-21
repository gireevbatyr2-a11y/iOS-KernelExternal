# iOS KernelExternal (external toolkit, iOS 15.0 – 17.3.1, arm64 + arm64e)

[![Build](https://github.com/gireevbatyr2-a11y/iOS-KernelExternal/actions/workflows/build.yml/badge.svg)](https://github.com/gireevbatyr2-a11y/iOS-KernelExternal/actions/workflows/build.yml)

**This is an external, not a jailbreak.** The tool runs outside the target
process: it acquires the target's task port via the stock `task_for_pid()`
(with entitlements), and afterwards reads/writes the process memory through the
public `mach_vm_*` interface. The kernel backend is used for exactly **one**
thing: zeroing the XNU `extmod` counters (`vm_extmod_statistics`) that every
cross-process `task_for_pid` bumps in both the caller and the target.

Userland kernel-external library in the spirit of opa334/Dopamine 3.x:
exploit backends provide kernel r/w, everything above it runs in userland on
top of **stock APIs** — `task_for_pid()` for task ports, and through the kernel
**only** the hygiene step: zeroing the XNU `extmod` counters
(`vm_extmod_statistics`) that every `task_for_pid` bumps in both the caller and
the target task.

```
┌─────────────────────────────────────────────────────────────────┐
│ app/ — External.app (UIKit external skeleton)                   │
│   process list → tap to attach → mach_vm read/write on the      │
│   task port → periodic extmod zeroing                           │
├─────────────────────────────────────────────────────────────────┤
│ your code / tweak / daemon                                      │
│   keTaskForPid(pid, &task, KE_TFP_FLAG_ZERO_BOTH)               │
├─────────────────────────────────────────────────────────────────┤
│ KernelExternal (libkernelexternal)                              │
│   • ke_task.c    stock task_for_pid wrapper                     │
│   • ke_extmod.c  vm_extmod_statistics: runtime self-calibration │
│                  + kernel-side zeroing (6 × i64 per task)       │
│   • ke_proc.c    task_t discovery: mach_port_kobject (primary), │
│                  allproc walk (fallback, needs offsets)         │
│   • ke_attach.c  external attach layer: task_for_pid +          │
│                  mach_vm_read_overwrite/write, process listing  │
│   • ke_offsets.c per-build offset table + defaults              │
│   • ke_dispatch.c version/arch matrix (Dopamine 3.x manifests)  │
├─────────────────────────────────────────────────────────────────┤
│ krw backends                                                    │
│   • kfd (landa / physpuppet / smith)  — vendored, header-only   │
│   • ClearSword                        — vendored, needs offsets │
└─────────────────────────────────────────────────────────────────┘
```

## What extmod counters are

In XNU, every `task_t` carries `vm_extmod_statistics_data_t extmod_statistics`
(`osfmk/kern/task.h`, struct in `osfmk/mach/vm_statistics.h`):

```c
struct vm_extmod_statistics {
    int64_t task_for_pid_count;             // this task was the TARGET of task_for_pid
    int64_t task_for_pid_caller_count;      // this task CALLED task_for_pid
    int64_t thread_creation_count;
    int64_t thread_creation_caller_count;
    int64_t thread_set_state_count;
    int64_t thread_set_state_caller_count;
} __attribute__((aligned(8)));
```

`extmod_statistics_incr_task_for_pid()` (osfmk/kern/extmod_statistics.c)
increments the counter on **both** sides for every cross-task `task_for_pid`.
The counters surface in crash reports (`extMods: caller/system/targeted`),
in `task_info(TASK_EXTMOD_INFO)` (flavor 19), and in msgtracer logging —
which is exactly why a userland-only `task_for_pid` flow leaves a trail.
This library leaves the kernel untouched except for the single hygiene
operation: writing 48 zero bytes over `task->extmod_statistics`.

No AMFI patches, no `task_self_addr` tricks for ports, no port forging:
`task_for_pid()` is called normally (entitlements required, see below).

## Backend matrix (from Dopamine 3.x exploit manifests)

| Backend      | iOS range                         | priority | offsets needed |
|--------------|-----------------------------------|----------|----------------|
| kfd physpuppet | 15.0 – 15.7.3, 16.0 – 16.3.1    | 1000     | allproc + staticBase |
| kfd landa      | 15.0 – 15.8.6, 16.0 – 16.6.1    | 900      | allproc + staticBase |
| ClearSword     | 15.0 – 18.7.1                   | 895      | full inpcb/socket table |
| kfd smith      | 15.0 – 15.7.6, 16.0 – 16.5      | 600      | allproc + staticBase (perf symbols on 16.x) |

Together this covers **iOS 15.0 – 17.3.1**: kfd flavors carry 15.0 – 16.6.1,
ClearSword carries everything up to 18.7.1 (hence 16.7 – 17.3.1).
`multicast_bytecopy` (15.0 – 15.1.1) and `weightBufs` (15.2 – 15.5 arm64e)
from Dopamine are not bundled; kfd covers those ranges.

Notes:
- kfd `landa` was patched by Apple in 15.8.7 — the matrix stops at 15.8.6,
  matching Dopamine.
- `physpuppet` on arm64e early 15.x may be unreliable; force `KE_BACKEND_KFD_LANDA`
  in that case (the AUTO selector will still try it as a fallback backend).
- ClearSword needs the per-build offsets table (see `offsets/`), which is why
  AUTO only picks it when the table entry for the running build exists.

## Requirements at runtime

- Kernel r/w backend initialized (`keInit`).
- The **calling** process needs `task_for_pid` entitlements:
  `com.apple.system-task-ports` (+ `com.apple.system-task-ports.read` for the
  read-only flavor). `TASK_EXTMOD_INFO` additionally needs
  `com.apple.private.security.no-container`-class entitlements. Under
  TrollStore or a jailbreak environment these are obtainable; otherwise the
  stock `task_for_pid` will fail with `KERN_FAILURE` before any kernel work.
- iOS 15.0 – 17.3.1. Rootless or rootful does not matter for the library
  itself; backends operate from userland.

## Usage

```c
#include <KernelExternal.h>

KEConfig cfg = { .verbose = true };
int r = keInit(&cfg);            // picks the best backend for this build
if (r != KE_OK) abort();

mach_port_t task = MACH_PORT_NULL;
kern_return_t kr = keTaskForPid(pid, &task, KE_TFP_FLAG_ZERO_BOTH);
// keTaskForPid == task_for_pid() + kernel-side zeroing of:
//   - target task extmod counters (KE_TFP_FLAG_ZERO_TARGET)
//   - our own caller counters     (KE_TFP_FLAG_ZERO_CALLER)

KEExtmodCounters c;
keGetExtmodOfPid(pid, &c);       // read counters via kernel r/w
keZeroExtmodOfPid(pid);          // zero them at any later time
keGetExtmodFromPort(task, &c);   // or read via stock TASK_EXTMOD_INFO

keDeinit();
```

Build with Theos:

```bash
make                 # builds libkernelexternal (rootless by default)
cd example && make   # builds kedemo CLI
cd app && make       # builds External.app (UIKit external skeleton)
# on device: ./kedemo <pid>
```

## The External.app skeleton (app/)

UIKit app that demonstrates the full external flow end to end:

1. `keInit()` — picks the best kernel backend for the running build.
2. `keProcessList()` — sysctl `KERN_PROC_ALL` process list.
3. Tap a process → `keAttach(pid, KE_TFP_FLAG_ZERO_BOTH)` — stock
   `task_for_pid` + kernel-side extmod hygiene on both sides.
4. Read/write arbitrary memory through the attached task port
   (`keReadMem`/`keWriteMem`, chunked `mach_vm_read_overwrite`/`mach_vm_write`).
5. "Zero extmods" button re-runs the hygiene at any time.

Install target: TrollStore (`.tipa` from CI artifacts) — the entitlements
(`com.apple.system-task-ports`, `com.apple.system-task-ports.read`,
`platform-application`, `com.apple.private.security.no-container`) are embedded
with `ldid` at build time.

## CI

GitHub Actions builds the library and the app on every push (macOS runner,
Theos + iPhoneOS16.5 SDK, `arm64` + `arm64e`, deployment target iOS 15.0 —
mirroring Dopamine's own CI recipe). Artifacts: `External.tipa`.

## Offsets

`src/ke_offsets_generated.h` ships empty — offsets are build-specific and must
be generated from real kernelcaches, exactly like Dopamine does with XPF at
jailbreak time (`DOJailbreaker.m → gatherSystemInformation`). See
`offsets/README.md` and `tools/gen_offsets/`.

The `vm_extmod_statistics` offset inside `struct task` is **not** in the table:
`ke_extmod.c` self-calibrates it at runtime by diffing the task struct before
and after controlled `task_for_pid` calls, cross-checking the caller and target
snapshots — build-independent by design.

## Vendor attribution

- `vendor/libkfd/` — libkfd from opa334/Dopamine 3.x (in-tree fork of
  Félix Poulin-Bélanger's kfd, adds `landa` and iOS 15.x tables). MIT.
- `vendor/clearsword_core/` — ClearSword exploit core from opa334/Dopamine 3.x
  (`Application/Dopamine/Exploits/ClearSword/exploit`). MIT.
- `vendor/clearsword_shim/` — minimal `libjailbreak` shims so the vendored
  ClearSword core builds standalone.

All vendored code keeps its original headers. Dopamine, kfd and XPF are MIT
licensed by their respective authors (opa334, Félix Poulin-Bélanger).

## Roadmap

- [x] External.app skeleton (attach via task_for_pid, mach_vm r/w, extmod zeroing)
- [ ] Free Fire OB55 external profile (target analysis deferred: Unity app,
      code lives in `Frameworks/UnityFramework.framework` (208 MB),
      IL2CPP metadata at `Data/Managed/Metadata/global-metadata.dat`, 56 MB)
- [ ] offsets table prefill for common builds (run tools/gen_offsets + KDK;
      verify against public sources — e.g. tomnific/iksof,
      lambertse/xnu-offset-finder, kaffeindecaf/kernel-deltas)

## Status / TODO

- [x] kernel-external API, krw facade, backend dispatch matrix
- [x] kfd backends wired (landa/physpuppet/smith), iOS 15/16 method selection
      (IOSurface on 15.x, sem_open on 16.x — mirrors Dopamine's kfd.m)
- [x] extmod runtime calibration + zeroing, `task_for_pid` wrapper
- [x] ClearSword vendored + backend wired through the shim
- [ ] optional PPL bypass plumbing (Titan/dmaFail) — not needed for the
      extmod hygiene scope (task structs are normal kernel memory)
