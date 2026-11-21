//
//  ke_internal.h — internal shared definitions
//
#ifndef KE_INTERNAL_H
#define KE_INTERNAL_H

#include "KernelExternal.h"
#include "ke_offsets.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern bool gKeVerbose;

// Logging: always append to /var/mobile/Documents/kernelexternal.log
// (user-requested — do not rely on the app UI for diagnostics).
// Keep a single static FILE* so re-init doesn't re-open constantly.
static FILE *ke_log_file(void) {
    static FILE *f = NULL;
    if (!f) {
        f = fopen("/var/mobile/Documents/kernelexternal.log", "a");
        if (f) setvbuf(f, NULL, _IOLBF, 0);
    }
    return f;
}

#define KE_LOG(...) do { \
    if (gKeVerbose) { \
        fprintf(stderr, "[ke] " __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
    FILE *_lf = ke_log_file(); \
    if (_lf) { \
        fprintf(_lf, "[%s %d] ", __FILE_NAME__, __LINE__); \
        fprintf(_lf, __VA_ARGS__); \
        fprintf(_lf, "\n"); \
        fflush(_lf); \
    } \
} while (0)
#define KE_FAIL(err, ...) do { fprintf(stderr, "[ke] error: " __VA_ARGS__); fprintf(stderr, "\n"); return (err); } while (0)

typedef struct KEEnvironment {
    int  major;           // parsed from kern.osproductversion
    int  minor;
    char build[32];       // kern.osversion, e.g. "20H18"
    char osVersion[16];   // kern.osproductversion, e.g. "16.7.10"
    char machine[64];     // hw.machine, e.g. "iPhone14,2"
    char arch[8];         // "arm64" or "arm64e" (kernel arch == SoC generation)
    bool isArm64e;
    bool verbose;
} KEEnvironment;

extern KEEnvironment keEnv;

// ke_env.c
void keEnvInit(void);

// ke_offsets.c
const KEBuildOffsets *keOffsetsForBuild(const char *build, const char *arch);
const KEBuildOffsets *keOffsetsForCurrentBuild(void);
void keOffsetsApplyDefaults(KEBuildOffsets *o);
void keOffsetsFillClearswordShim(const KEBuildOffsets *o);

// Backends
typedef struct KEBackendOps {
    const char *name;
    KEBackendID id;
    int (*init)(const KEConfig *config);
    void (*deinit)(void);
    int (*kreadbuf)(uint64_t kaddr, void *out, size_t size);
    int (*kwritebuf)(uint64_t kaddr, const void *in, size_t size);
    uint64_t (*vtophys)(uint64_t kaddr);
} KEBackendOps;

// ke_backend_kfd.c
int keKfdInit(KEBackendID backend, const KEConfig *config);
extern const KEBackendOps keBackendKfdPhyspuppet;
extern const KEBackendOps keBackendKfdLanda;
extern const KEBackendOps keBackendKfdSmith;

// ke_backend_clearsword.c
extern const KEBackendOps keBackendClearsword;

// ke_dispatch.c
const KEBackendOps *keBackendForID(KEBackendID id);
int keDispatchCandidates(KEBackendID preferred, KEBackendID *out, int maxOut);

// ke_offsets.c

// ke_proc.c
uint64_t keTaskOfTaskPort(mach_port_t taskPort);
uint64_t keTaskOfPidAllproc(pid_t pid, uint64_t *procOut);

// ke_extmod.c
int keCalibrateExtmodOffset(void);
int64_t keGetExtmodOffset(void);
void keInvalidateExtmodCalibration(void);
int keGetExtmodOfTask(uint64_t taskKaddr, KEExtmodCounters *out);
int keZeroExtmodOfTask(uint64_t taskKaddr);

// Runtime-derived proc layout (kfd sem_open path, no offsets table)
extern uint64_t gKeKfdKernelProc;
extern uint64_t gKeKfdCurrentProc;
extern uint64_t gKeRuntimeProcPid;
extern uint64_t gKeRuntimeProcTask;
extern uint64_t gKeRuntimeProcObjectSize;

// ke.c
extern const KEBackendOps *gActiveBackend;
extern bool gKeInitialized;
extern bool gKeKrwIsPerf;

#endif // KE_INTERNAL_H
