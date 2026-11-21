//
//  ke_krw.c — kernel read/write facade over the active backend
//
#include "ke_internal.h"

int keKreadBuf(uint64_t kaddr, void *out, size_t size)
{
    if (!keIsInitialized()) return KE_ERR_NOT_INITIALIZED;
    if (!gActiveBackend || !gActiveBackend->kreadbuf) return KE_ERR_EXPLOIT_FAILED;
    if (!kaddr) return KE_ERR_INVALID_ARGUMENT;
    return gActiveBackend->kreadbuf(kaddr, out, size);
}

int keKwriteBuf(uint64_t kaddr, const void *in, size_t size)
{
    if (!keIsInitialized()) return KE_ERR_NOT_INITIALIZED;
    if (!gActiveBackend || !gActiveBackend->kwritebuf) return KE_ERR_EXPLOIT_FAILED;
    if (!kaddr) return KE_ERR_INVALID_ARGUMENT;
    return gActiveBackend->kwritebuf(kaddr, in, size);
}

int keKread64(uint64_t kaddr, uint64_t *out)
{
    return keKreadBuf(kaddr, out, sizeof(uint64_t));
}

int keKwrite64(uint64_t kaddr, uint64_t value)
{
    return keKwriteBuf(kaddr, &value, sizeof(uint64_t));
}

uint64_t keVtophys(uint64_t kaddr)
{
    if (!keIsInitialized() || !gActiveBackend || !gActiveBackend->vtophys) return 0;
    return gActiveBackend->vtophys(kaddr);
}
