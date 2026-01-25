#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) 1;
static int (*bpf_redirect_map)(void *map, int key, int flags) = (void *) 51;

#endif
