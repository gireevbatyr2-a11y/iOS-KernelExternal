//
//  ke.c — library lifecycle
//
#include "ke_internal.h"
#include <sys/time.h>

// landa (kfd) may only fire once per boot — a second run in the same
// session panics the kernel ("shared_region_pager_data_return").
// We persist the boot session id the first time the exploit is attempted
// and refuse any further attempts until the device reboots.
#define KE_BOOT_MARKER "/var/mobile/Documents/kernelexternal.boot"

static void keBootSessionId(char out[65])
{
    char buf[128] = {0};
    size_t sz = sizeof(buf);
    if (sysctlbyname("kern.bootsessionuuid", buf, &sz, NULL, 0) == 0 && buf[0]) {
        strlcpy(out, buf, 65);
        return;
    }
    struct timeval tv;
    size_t tsz = sizeof(tv);
    if (sysctlbyname("kern.boottime", &tv, &tsz, NULL, 0) == 0) {
        snprintf(out, 65, "boot-%lld", (long long)tv.tv_sec);
        return;
    }
    strlcpy(out, "unknown", 65);
}

static bool keBootMarkerMatches(const char *uuid)
{
    FILE *f = fopen(KE_BOOT_MARKER, "r");
    if (!f) return false;
    char stored[160] = {0};
    size_t n = fread(stored, 1, sizeof(stored) - 1, f);
    fclose(f);
    while (n && (stored[n-1] == '\n' || stored[n-1] == '\r')) stored[--n] = 0;
    return n > 0 && strcmp(stored, uuid) == 0;
}

static void keBootMarkerWrite(const char *uuid)
{
    FILE *f = fopen(KE_BOOT_MARKER, "w");
    if (!f) {
        KE_LOG("warning: cannot write boot marker %s", KE_BOOT_MARKER);
        return;
    }
    fprintf(f, "%s\n", uuid);
    fclose(f);
}

const KEBackendOps *gActiveBackend = NULL;
bool gKeKrwIsPerf = false;

bool keIsInitialized(void)
{
    return gKeInitialized;
}

const char *keActiveBackendName(void)
{
    return gActiveBackend ? gActiveBackend->name : "none";
}

const char *keBackendName(KEBackendID id)
{
    const KEBackendOps *ops = keBackendForID(id);
    return ops ? ops->name : NULL;
}

int keInit(const KEConfig *config)
{
    if (!config) return KE_ERR_INVALID_ARGUMENT;
    if (gKeInitialized) keDeinit();

    gKeVerbose = config->verbose;
    keEnvInit();
    keEnv.verbose = config->verbose;

    const KEBuildOffsets *o = keOffsetsForCurrentBuild();
    if (o) {
        keOffsetsFillClearswordShim(o);
    }

    KEBackendID candidates[5] = { 0 };
    int n = keDispatchCandidates(config->preferredBackend, candidates, 5);
    if (n == 0) {
        KE_LOG("no backend supports %s %s (%s)", keEnv.osVersion, keEnv.build, keEnv.arch);
        return KE_ERR_UNSUPPORTED_VERSION;
    }

    char bootId[65];
    keBootSessionId(bootId);

    int lastErr = KE_ERR_BACKEND_UNSUPPORTED;
    for (int i = 0; i < n; i++) {
        const KEBackendOps *ops = keBackendForID(candidates[i]);
        if (!ops || !ops->init) continue;
        KE_LOG("trying backend %s ...", ops->name);
        if (ops->id >= KE_BACKEND_KFD_PHYSPUPPET && ops->id <= KE_BACKEND_KFD_SMITH) {
            // kfd (landa) is one-shot per boot: the shared-region pager cannot
            // survive a second run in the same session. Guard kfd only.
            if (keBootMarkerMatches(bootId)) {
                KE_LOG("boot %s: kfd already used this session — skipping", bootId);
                lastErr = KE_ERR_EXPLOIT_ALREADY_USED;
                continue;
            }
            keBootMarkerWrite(bootId);
            KE_LOG("boot %s marked as kfd-attempted", bootId);
        }
        int r = ops->init(config);
        if (r == KE_OK) {
            gActiveBackend = ops;
            gKeInitialized = true;
            keUsermemInit();
            uint64_t kb = keKernelBase();
            KE_LOG("backend %s active; usermem ready=%d kernelBase=0x%llx",
                   ops->name, keUsermemReady() ? 1 : 0, (unsigned long long)kb);
            return KE_OK;
        }
        lastErr = r;
        KE_LOG("backend %s failed: %d", ops->name, r);
    }
    return lastErr;
}

void keDeinit(void)
{
    if (gActiveBackend && gActiveBackend->deinit) {
        gActiveBackend->deinit();
    }
    gActiveBackend = NULL;
    gKeInitialized = false;
    keInvalidateExtmodCalibration();
}

const char *keErrorString(int error)
{
    switch (error) {
    case 0:                      return "success";
    case KE_ERR_UNSUPPORTED_VERSION: return "unsupported iOS version";
    case KE_ERR_UNSUPPORTED_DEVICE:  return "unsupported device";
    case KE_ERR_EXPLOIT_FAILED:      return "kernel exploit failed";
    case KE_ERR_OFFSETS_MISSING:     return "offsets missing for this build";
    case KE_ERR_NOT_INITIALIZED:     return "library not initialized";
    case KE_ERR_NO_KERNEL_MEMORY:    return "no kernel memory access";
    case KE_ERR_TFP_FAILED:          return "task_for_pid failed";
    case KE_ERR_CALIBRATION_FAILED:  return "extmod offset calibration failed";
    case KE_ERR_INVALID_ARGUMENT:    return "invalid argument";
    case KE_ERR_BACKEND_UNSUPPORTED: return "backend unsupported for this target";
    case KE_ERR_EXPLOIT_ALREADY_USED: return "exploit already used this boot — reboot the device to try again";
    default:                     return "unknown error";
    }
}
