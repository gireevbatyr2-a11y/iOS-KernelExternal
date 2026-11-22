//
//  ke_usermem.c — user-space memory access of OTHER processes,
//  Dopamine-style: proc -> task -> vm_map -> pmap -> ttep, then a manual
//  ARM page-table walk, then read/write the physical page through the
//  kernel physmap alias (phystokv). This is exactly the mechanism Dopamine
//  3.x builds after its kernel exploit (libjailbreak translation.c/physrw.c),
//  and the mechanism a jailbroken lara/ffvn gets from physrw handoff —
//  implemented here purely on top of the external's kernel r/w backend.
//
//  Constants (ptov_table content, gPhysBase/gVirtBase/gPhysSize values,
//  struct offsets) are boot-constant per build and are saved statically by
//  the vendored XPF resolution step (lara.* keys in NSUserDefaults).
//
//  Kernel base derivation:
//  - darksword backend: ds_get_kernel_base() (slide from its own primitives)
//  - kfd backends: proc0 discovery trick — the runtime address of the
//    allproc list head is proc0->p_list.le_prev (kread-able via the kfd
//    primitives), so base = allproc_runtime - allproc_static_offset.
//

#include "ke_internal.h"

#include <stdlib.h>
#include <sys/sysctl.h>

#if __has_include("../vendor/darksword/darksword.h")
#include "../vendor/darksword/darksword.h"
#include "../vendor/darksword/utils.h"
#define KE_UM_HAS_DARKSWORD 1
#endif

// ---------------------------------------------------------------------------
// ARM translation-table constants (Dopamine libjailbreak pte.h)
// ---------------------------------------------------------------------------

#define KE_TTE_VALID        0x0000000000000001ULL
#define KE_TTE_TYPE_MASK    0x0000000000000002ULL
#define KE_TTE_TYPE_L3BLOCK 0x0000000000000002ULL
#define KE_TTE_TYPE_BLOCK   0x0000000000000000ULL
#define KE_TTE_TABLE_MASK   0x0000fffffffff000ULL
#define KE_TTE_PA_MASK      0x0000fffffffff000ULL

#define KE_PMAP_TT_L0_LEVEL 0x0
#define KE_PMAP_TT_L1_LEVEL 0x1
#define KE_PMAP_TT_L2_LEVEL 0x2
#define KE_PMAP_TT_L3_LEVEL 0x3

// 16K granule (A9+)
#define KE_16K_TT_L0_OFFMASK     0x00007fffffffffffull
#define KE_16K_TT_L0_SHIFT       47
#define KE_16K_TT_L0_INDEX_MASK  0x0000800000000000ull
#define KE_16K_TT_L1_OFFMASK     0x0000000fffffffffull
#define KE_16K_TT_L1_SHIFT       36
#define KE_16K_TT_L1_INDEX_MASK  0x0000007000000000ull
#define KE_16K_TT_L2_OFFMASK     0x0000000001ffffffull
#define KE_16K_TT_L2_SHIFT       25
#define KE_16K_TT_L2_INDEX_MASK  0x0000000ffe000000ull
#define KE_16K_TT_L3_OFFMASK     0x0000000000003fffull
#define KE_16K_TT_L3_SHIFT       14
#define KE_16K_TT_L3_INDEX_MASK  0x0000000001ffc000ull

// 4K granule (A8)
#define KE_4K_TT_L0_OFFMASK     0x0000007fffffffffull
#define KE_4K_TT_L0_SHIFT       39
#define KE_4K_TT_L0_INDEX_MASK  0x0000ff8000000000ull
#define KE_4K_TT_L1_OFFMASK     0x000000003fffffffull
#define KE_4K_TT_L1_SHIFT       30
#define KE_4K_TT_L1_INDEX_MASK  0x0000003fc0000000ull
#define KE_4K_TT_L2_OFFMASK     0x00000000001fffffull
#define KE_4K_TT_L2_SHIFT       21
#define KE_4K_TT_L2_INDEX_MASK  0x000000003fe00000ull
#define KE_4K_TT_L3_OFFMASK     0x0000000000000fffull
#define KE_4K_TT_L3_SHIFT       12
#define KE_4K_TT_L3_INDEX_MASK  0x00000000000ff000ull

#define KE_PTOV_TABLE_SIZE 8

typedef struct {
    uint64_t offMask;
    uint64_t shift;
    uint64_t indexMask;
    uint64_t validMask;
    uint64_t typeMask;
    uint64_t typeBlock;
} ke_tt_level;

typedef struct {
    uint64_t pa;
    uint64_t va;
    uint64_t len;
} ke_ptov_entry;

// ---------------------------------------------------------------------------
// Saved constants (vendored XPF resolution, per build)
// ---------------------------------------------------------------------------

static uint64_t gUmGPhysBase = 0;   // value
static uint64_t gUmGPhysSize = 0;   // value
static uint64_t gUmGVirtBase = 0;   // value
static ke_ptov_entry gUmPtov[KE_PTOV_TABLE_SIZE];
static bool gUmPtovValid = false;
static uint64_t gUmKernelBase = 0;  // runtime kernel base (per boot)
static uint64_t gUmPageSize = 0x4000;
static uint64_t gUmVmMapPmapOff = 0;
static uint64_t gUmProcPidOff = 0;
static uint64_t gUmProcTaskOff = 0;
static uint64_t gUmProcNextOff = 0;
static bool gUmReady = false;

// Read a saved value from the vendored offsets resolution (keys are stored
// via NSUserDefaults in this app's own preference domain, prefixed "lara.").
static uint64_t ke_saved_u64(const char *key)
{
    static CFStringRef domain = NULL;
    if (!domain) {
        CFBundleRef b = CFBundleGetMainBundle();
        CFStringRef id = b ? CFBundleGetIdentifier(b) : NULL;
        domain = id ?: CFSTR("lara");
        CFRetain(domain);
    }

    CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
    CFTypeRef v = CFPreferencesCopyAppValue(k, domain);
    CFRelease(k);
    if (!v) return 0;

    uint64_t out = 0;
    if (CFGetTypeID(v) == CFNumberGetTypeID()) {
        CFNumberGetValue((CFNumberRef)v, kCFNumberSInt64Type, &out);
    } else if (CFGetTypeID(v) == CFStringGetTypeID()) {
        char buf[64] = {0};
        if (CFStringGetCString((CFStringRef)v, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            out = strtoull(buf, NULL, 0);
        }
    }
    CFRelease(v);
    return out;
}

// ---------------------------------------------------------------------------
// phystokv — physical to kernel virtual (Dopamine translation.c phystokv)
// ---------------------------------------------------------------------------

uint64_t kePhystokv(uint64_t pa)
{
    if (!gUmReady) return 0;

    if (gUmPtovValid) {
        for (int i = 0; i < KE_PTOV_TABLE_SIZE && gUmPtov[i].len != 0; i++) {
            if (pa >= gUmPtov[i].pa && pa < (gUmPtov[i].pa + gUmPtov[i].len)) {
                return pa - gUmPtov[i].pa + gUmPtov[i].va;
            }
        }
    }

    if (gUmGPhysBase && gUmGVirtBase && gUmGPhysSize) {
        if (pa < gUmGPhysBase || (pa - gUmGPhysBase) >= gUmGPhysSize) return 0;
        return pa - gUmGPhysBase + gUmGVirtBase;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// ARM page-table walk for an arbitrary user pmap (Dopamine vtophys_lvl)
// ---------------------------------------------------------------------------

static void ke_um_levels(ke_tt_level out[4])
{
    if (gUmPageSize == 0x4000) {
        out[0] = (ke_tt_level){KE_16K_TT_L0_OFFMASK, KE_16K_TT_L0_SHIFT, KE_16K_TT_L0_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_BLOCK};
        out[1] = (ke_tt_level){KE_16K_TT_L1_OFFMASK, KE_16K_TT_L1_SHIFT, KE_16K_TT_L1_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_BLOCK};
        out[2] = (ke_tt_level){KE_16K_TT_L2_OFFMASK, KE_16K_TT_L2_SHIFT, KE_16K_TT_L2_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_BLOCK};
        out[3] = (ke_tt_level){KE_16K_TT_L3_OFFMASK, KE_16K_TT_L3_SHIFT, KE_16K_TT_L3_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_L3BLOCK};
    } else {
        out[0] = (ke_tt_level){KE_4K_TT_L0_OFFMASK, KE_4K_TT_L0_SHIFT, KE_4K_TT_L0_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_BLOCK};
        out[1] = (ke_tt_level){KE_4K_TT_L1_OFFMASK, KE_4K_TT_L1_SHIFT, KE_4K_TT_L1_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_BLOCK};
        out[2] = (ke_tt_level){KE_4K_TT_L2_OFFMASK, KE_4K_TT_L2_SHIFT, KE_4K_TT_L2_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_BLOCK};
        out[3] = (ke_tt_level){KE_4K_TT_L3_OFFMASK, KE_4K_TT_L3_SHIFT, KE_4K_TT_L3_INDEX_MASK, KE_TTE_VALID, KE_TTE_TYPE_MASK, KE_TTE_TYPE_L3BLOCK};
    }
}

// ttep = PHYSICAL address of the L1 table (pmap + 0x8, struct pmap.ttep)
static uint64_t ke_um_vtophys_user(uint64_t ttep, uint64_t va)
{
    ke_tt_level lvl[4];
    ke_um_levels(lvl);

    for (uint64_t curLevel = KE_PMAP_TT_L1_LEVEL; curLevel <= KE_PMAP_TT_L3_LEVEL; curLevel++) {
        const ke_tt_level *l = &lvl[curLevel];
        uint64_t tteIndex = (va & l->indexMask) >> l->shift;
        uint64_t ttePa = ttep + (tteIndex * sizeof(uint64_t));
        uint64_t tteKaddr = kePhystokv(ttePa);
        if (!tteKaddr) return 0;
        uint64_t tte = 0;
        if (keKread64(tteKaddr, &tte) != 0) return 0;
        if ((tte & l->validMask) != l->validMask) return 0;
        if ((tte & l->typeMask) == l->typeBlock) {
            return ((tte & KE_TTE_PA_MASK & ~l->offMask) | (va & l->offMask));
        }
        ttep = tte & KE_TTE_TABLE_MASK;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Kernel base
// ---------------------------------------------------------------------------

static uint64_t ke_um_proc_object_size(void)
{
    uint64_t ps = ke_saved_u64("lara.kernproc_size");
    if (ps) return ps;
    return (keEnv.major >= 16) ? 0x730 : 0x4b0;
}

uint64_t keKernelBase(void)
{
    if (gUmKernelBase) return gUmKernelBase;

#if KE_UM_HAS_DARKSWORD
    if (gActiveBackend && gActiveBackend->id == KE_BACKEND_DARKSWORD && ds_is_ready()) {
        uint64_t b = ds_get_kernel_base();
        if (b) {
            gUmKernelBase = b;
            KE_LOG("usermem: kernel base (darksword) 0x%llx", (unsigned long long)b);
            return b;
        }
    }
#endif

    // kfd: proc0 trick. First, find ANY proc (kfd tracks the runtime proc).
    uint64_t cur = gKeKfdCurrentProc;
#if KE_UM_HAS_DARKSWORD
    if (!cur && gActiveBackend && gActiveBackend->id == KE_BACKEND_DARKSWORD && ds_is_ready()) {
        cur = procbypid(getpid());
    }
#endif
    if (!cur) return 0;

    // Walk le_prev towards proc0. For a real proc, le_prev points at the
    // previous proc's le_next field, so kread(prev) == current proc. For
    // proc0, le_prev points at the allproc list head variable itself, whose
    // value is proc0 — not our p. That is exactly the runtime address of
    // the allproc symbol, which gives us the kernel base for free.
    uint64_t allprocRuntime = 0;
    uint64_t p = cur;
    for (int i = 0; i < 8192 && p; i++) {
        uint64_t prev = 0;
        if (keKread64(p + 0x8, &prev) != 0) break;
        prev = keUnsignKaddr(prev);
        if (!prev) break;

        uint64_t prevVal = 0;
        if (keKread64(prev + 0x0, &prevVal) != 0) break;
        prevVal = keUnsignKaddr(prevVal);
        if (prevVal == p) {
            p = prev; // real previous proc
            continue;
        }
        allprocRuntime = prev; // &allproc
        break;
    }
    if (!allprocRuntime) return 0;

    uint64_t allprocOff = ke_saved_u64("lara.allprocoff");
    if (!allprocOff) return 0;

    uint64_t base = allprocRuntime - allprocOff;
    if ((base & 0xfff) != 0) return 0; // must be page aligned

    gUmKernelBase = base;
    KE_LOG("usermem: kernel base (kfd, allproc) 0x%llx", (unsigned long long)base);
    return base;
}

// ---------------------------------------------------------------------------
// Process discovery
// ---------------------------------------------------------------------------

// Find a target proc by pid.
// - darksword backend: vendored procbypid() (ds primitives, base-aware)
// - otherwise: allproc walk using the saved static offset + derived base
static uint64_t ke_um_proc_of_pid(pid_t pid)
{
#if KE_UM_HAS_DARKSWORD
    if (gActiveBackend && gActiveBackend->id == KE_BACKEND_DARKSWORD && ds_is_ready()) {
        uint64_t p = procbypid(pid);
        if (p) return keUnsignKaddr(p);
    }
#endif

    uint64_t base = keKernelBase();
    if (!base) return 0;

    uint64_t allprocOff = ke_saved_u64("lara.allprocoff");
    if (!allprocOff) return 0;

    uint64_t head = 0;
    if (keKread64(base + allprocOff, &head) != 0) return 0;
    head = keUnsignKaddr(head);
    if (!head) return 0;

    uint64_t proc = head;
    for (int i = 0; i < 4096 && proc; i++) {
        int32_t curPid = 0;
        if (keKreadBuf(proc + gUmProcPidOff, &curPid, sizeof(curPid)) != 0) return 0;
        if (curPid == pid) return proc;
        uint64_t next = 0;
        if (keKread64(proc + gUmProcNextOff, &next) != 0) return 0;
        next = keUnsignKaddr(next);
        if (!next || next == proc) return 0;
        proc = next;
    }
    return 0;
}

// proc -> task -> map -> pmap -> ttep, shared by read/write
static int ke_um_target_ttep(pid_t pid, uint64_t *ttepOut)
{
    uint64_t proc = ke_um_proc_of_pid(pid);
    if (!proc) return KE_ERR_PROC_NOT_FOUND;

    uint64_t task = 0;
    if (gUmProcTaskOff) {
        if (keKread64(proc + gUmProcTaskOff, &task) != 0) return KE_ERR_PROC_NOT_FOUND;
        task = keUnsignKaddr(task);
    }
    if (!task) task = proc + ke_um_proc_object_size();
    if (!task) return KE_ERR_PROC_NOT_FOUND;

    uint64_t map = 0;
    if (keKread64(task + 0x28, &map) != 0) return KE_ERR_KRW;
    map = keUnsignKaddr(map);
    if (!map) return KE_ERR_KRW;

    uint64_t pmap = 0;
    if (keKread64(map + gUmVmMapPmapOff, &pmap) != 0) return KE_ERR_KRW;
    pmap = keUnsignKaddr(pmap);
    if (!pmap) return KE_ERR_KRW;

    uint64_t ttep = 0;
    if (keKread64(pmap + 0x8, &ttep) != 0) return KE_ERR_KRW; // struct pmap.ttep = 0x8
    ttep = keUnsignKaddr(ttep) & KE_TTE_TABLE_MASK;
    if (!ttep) return KE_ERR_KRW;

    *ttepOut = ttep;
    return KE_OK;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int keUserRead(pid_t pid, uint64_t uaddr, void *buf, size_t size)
{
    if (!gUmReady || !buf || !size) return KE_ERR_INVALID_ARGUMENT;
    if (!gUmPtovValid && !gUmGPhysBase) return KE_ERR_OFFSETS_MISSING;

    uint64_t ttep = 0;
    int r = ke_um_target_ttep(pid, &ttep);
    if (r != KE_OK) return r;

    uint8_t *out = (uint8_t *)buf;
    size_t done = 0;
    while (done < size) {
        uint64_t va = uaddr + done;
        uint64_t offInPage = va & (gUmPageSize - 1);
        size_t chunk = size - done;
        if (chunk > gUmPageSize - offInPage) chunk = gUmPageSize - offInPage;

        uint64_t pa = ke_um_vtophys_user(ttep, va & ~(gUmPageSize - 1));
        if (!pa) return KE_ERR_KRW;
        uint64_t kaddr = kePhystokv(pa);
        if (!kaddr) return KE_ERR_KRW;
        if (keKreadBuf(kaddr, out + done, chunk) != 0) return KE_ERR_KRW;
        done += chunk;
    }
    return KE_OK;
}

int keUserWrite(pid_t pid, uint64_t uaddr, const void *buf, size_t size)
{
    if (!gUmReady || !buf || !size) return KE_ERR_INVALID_ARGUMENT;
    if (!gUmPtovValid && !gUmGPhysBase) return KE_ERR_OFFSETS_MISSING;

    uint64_t ttep = 0;
    int r = ke_um_target_ttep(pid, &ttep);
    if (r != KE_OK) return r;

    const uint8_t *in = (const uint8_t *)buf;
    size_t done = 0;
    while (done < size) {
        uint64_t va = uaddr + done;
        uint64_t offInPage = va & (gUmPageSize - 1);
        size_t chunk = size - done;
        if (chunk > gUmPageSize - offInPage) chunk = gUmPageSize - offInPage;

        uint64_t pa = ke_um_vtophys_user(ttep, va & ~(gUmPageSize - 1));
        if (!pa) return KE_ERR_KRW;
        uint64_t kaddr = kePhystokv(pa);
        if (!kaddr) return KE_ERR_KRW;
        if (keKwriteBuf(kaddr, in + done, chunk) != 0) return KE_ERR_KRW;
        done += chunk;
    }
    return KE_OK;
}

// ---------------------------------------------------------------------------
// Init — load saved static constants
// ---------------------------------------------------------------------------

void keUsermemLoadSaved(void)
{
    gUmVmMapPmapOff = ke_saved_u64("lara.offset.vmmap_pmap");
    gUmProcPidOff = ke_saved_u64("lara.offset.proc_pid");
    gUmProcTaskOff = ke_saved_u64("lara.offset.proc_task");
    gUmProcNextOff = ke_saved_u64("lara.offset.proc_next");
    if (!gUmVmMapPmapOff) gUmVmMapPmapOff = 0x20;
    if (!gUmProcPidOff) gUmProcPidOff = (keEnv.major >= 16) ? 0x68 : 0x60;
    if (!gUmProcTaskOff) gUmProcTaskOff = (keEnv.major >= 16) ? 0 : 0x10;
    if (!gUmProcNextOff) gUmProcNextOff = 0x0;
}

void keUsermemInit(void)
{
    size_t sz = sizeof(gUmPageSize);
    if (sysctlbyname("hw.pagesize", &gUmPageSize, &sz, NULL, 0) != 0 || !gUmPageSize) {
        gUmPageSize = 0x4000;
    }

    keUsermemLoadSaved();

    gUmGPhysBase = ke_saved_u64("lara.gphysbase_val");
    gUmGPhysSize = ke_saved_u64("lara.gphyssize_val");
    gUmGVirtBase = ke_saved_u64("lara.gvirtbase_val");

    // ptov table content saved as hex string "pa:va:len pa:va:len ..."
    static CFStringRef domain = NULL;
    if (!domain) {
        CFBundleRef b = CFBundleGetMainBundle();
        CFStringRef id = b ? CFBundleGetIdentifier(b) : NULL;
        domain = id ?: CFSTR("lara");
        CFRetain(domain);
    }
    CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, "lara.ptov_content", kCFStringEncodingUTF8);
    CFTypeRef v = CFPreferencesCopyAppValue(k, domain);
    CFRelease(k);
    gUmPtovValid = false;
    if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
        char buf[2048] = {0};
        if (CFStringGetCString((CFStringRef)v, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            memset(gUmPtov, 0, sizeof(gUmPtov));
            int n = 0;
            const char *p = buf;
            while (*p && n < KE_PTOV_TABLE_SIZE) {
                unsigned long long pa = 0, va = 0, len = 0;
                int consumed = 0;
                if (sscanf(p, "%llx:%llx:%llx%n", &pa, &va, &len, &consumed) == 3) {
                    gUmPtov[n].pa = pa;
                    gUmPtov[n].va = va;
                    gUmPtov[n].len = len;
                    n++;
                    p += consumed;
                } else break;
                while (*p == ' ') p++;
            }
            if (n > 0) gUmPtovValid = true;
            KE_LOG("usermem: ptov entries=%d", n);
        }
    }
    if (v) CFRelease(v);

    gUmReady = (gUmPtovValid || (gUmGPhysBase && gUmGVirtBase && gUmGPhysSize));
    KE_LOG("usermem: init ready=%d pageSize=0x%llx physBase=0x%llx virtBase=0x%llx pmapOff=0x%llx",
           gUmReady ? 1 : 0, (unsigned long long)gUmPageSize,
           (unsigned long long)gUmGPhysBase, (unsigned long long)gUmGVirtBase,
           (unsigned long long)gUmVmMapPmapOff);
}

bool keUsermemReady(void)
{
    return gUmReady;
}
