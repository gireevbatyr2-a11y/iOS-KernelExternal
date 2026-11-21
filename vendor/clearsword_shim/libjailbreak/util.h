//
//  shim/libjailbreak/util.h — walk_backtrace() used by ClearSword error paths
//
#ifndef LIBJAILBREAK_UTIL_SHIM_H
#define LIBJAILBREAK_UTIL_SHIM_H

#include <stdbool.h>
#include <libunwind.h>

static inline bool walk_backtrace(bool (^block)(int frame_index, unw_word_t pc, unw_word_t offset, const char *symbol_name))
{
    unw_context_t context = { 0 };
    unw_cursor_t cursor = { 0 };
    if (unw_getcontext(&context) != 0) return false;
    if (unw_init_local(&cursor, &context) != 0) return false;

    int frame = 0;
    while (unw_step(&cursor) > 0) {
        unw_word_t pc = 0, off = 0;
        char name[256] = { 0 };
        unw_get_reg(&cursor, UNW_REG_IP, &pc);
        unw_get_proc_name(&cursor, name, sizeof(name), &off);
        if (!block(frame++, pc, off, name[0] ? name : NULL)) break;
    }
    return true;
}

#endif
