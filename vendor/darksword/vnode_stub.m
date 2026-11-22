//  vnode_stub.m — stub: lara vnode helpers unused in External flow
#import "vnode.h"
uint64_t vnodebychdir(const char *path) { (void)path; return 0; }
uint64_t vnodebyfd(int fd) { (void)fd; return 0; }
uint64_t vnodebyopen(const char *path) { (void)path; return 0; }
uint64_t vn_folderredirect(const char *to, const char *from) { (void)to; (void)from; return 0; }
bool vn_folderunredirect(const char *folder, uint64_t orig_to_v_data) { (void)folder; (void)orig_to_v_data; return false; }
char* vn_vname(uint64_t vnode) { (void)vnode; return NULL; }
uint64_t vn_childvnode(uint64_t vnode, const char* child, uint64_t blacklist) { (void)vnode; (void)child; (void)blacklist; return 0; }
bool vn_fileredirect(const char *to, const char *from, uint64_t* orig_to_vnode, uint64_t* orig_to_v_data) { (void)to; (void)from; (void)orig_to_vnode; (void)orig_to_v_data; return false; }
bool vn_fileunredirect(uint64_t orig_to_vnode, uint64_t orig_to_v_data) { (void)orig_to_vnode; (void)orig_to_v_data; return false; }
uint64_t vn_fsnode(uint64_t vp) { (void)vp; return 0; }
