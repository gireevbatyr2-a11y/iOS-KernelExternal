//
//  ke.c — library lifecycle
//
#include "ke_internal.h"

const KEBackendOps *gActiveBackend = NULL;

bool keIsInitialized(void)
{
    return gKeInitialized;
}

const char *keActiveBackendName(void)
{
    return gActiveBackend ? gActiveBackend->name : NULL;
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

    KEBackendID candidates[4] = { 0 };
    int n = keDispatchCandidates(config->preferredBackend, candidates, 4);
    if (n == 0) {
        KE_LOG("no backend supports %s %s (%s)", keEnv.osVersion, keEnv.build, keEnv.arch);
        return KE_ERR_UNSUPPORTED_VERSION;
    }

    int lastErr = KE_ERR_BACKEND_UNSUPPORTED;
    for (int i = 0; i < n; i++) {
        const KEBackendOps *ops = keBackendForID(candidates[i]);
        if (!ops || !ops->init) continue;
        KE_LOG("trying backend %s ...", ops->name);
        int r = ops->init(config);
        if (r == KE_OK) {
            gActiveBackend = ops;
            gKeInitialized = true;
            KE_LOG("backend %s active", ops->name);
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
