//
//  ke_env.c — device/environment detection
//
#include "ke_internal.h"

KEEnvironment keEnv = { 0 };
bool gKeVerbose = false;
bool gKeInitialized = false;

static bool keSysctlStr(const char *name, char *out, size_t outSize)
{
    size_t size = outSize;
    if (sysctlbyname(name, out, &size, NULL, 0) != 0) return false;
    out[outSize - 1] = '\0';
    return true;
}

// A12 (iPhone XS/XR generation) and newer run an arm64e kernel.
// Everything older runs arm64. iPad8,x is A12X/A12Z.
static bool keMachineIsArm64e(const char *machine)
{
    static const char *const arm64ePrefixes[] = {
        "iPhone11,", "iPhone12,", "iPhone13,", "iPhone14,",
        "iPhone15,", "iPhone16,", "iPhone17,",
        "iPad8,", "iPad13,", "iPad14,", "iPad15,", "iPad16,",
    };
    for (size_t i = 0; i < sizeof(arm64ePrefixes) / sizeof(arm64ePrefixes[0]); i++) {
        size_t len = strlen(arm64ePrefixes[i]);
        if (strncmp(machine, arm64ePrefixes[i], len) == 0) return true;
    }
    return false;
}

void keEnvInit(void)
{
    memset(&keEnv, 0, sizeof(keEnv));
    keSysctlStr("kern.osversion", keEnv.build, sizeof(keEnv.build));
    keSysctlStr("kern.osproductversion", keEnv.osVersion, sizeof(keEnv.osVersion));
    if (!keSysctlStr("hw.machine", keEnv.machine, sizeof(keEnv.machine))) {
        strlcpy(keEnv.machine, "unknown", sizeof(keEnv.machine));
    }
    keEnv.isArm64e = keMachineIsArm64e(keEnv.machine);
    strlcpy(keEnv.arch, keEnv.isArm64e ? "arm64e" : "arm64", sizeof(keEnv.arch));

    keEnv.major = (int)strtol(keEnv.osVersion, NULL, 10);
    const char *dot = strchr(keEnv.osVersion, '.');
    keEnv.minor = dot ? (int)strtol(dot + 1, NULL, 10) : 0;

    KE_LOG("env: build=%s os=%s machine=%s arch=%s", keEnv.build, keEnv.osVersion, keEnv.machine, keEnv.arch);
}
