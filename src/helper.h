#ifndef PITT_ECE_2162_SPECTRE_HELPER_H
#define PITT_ECE_2162_SPECTRE_HELPER_H

#include "sched.h"

static inline void wait() {
    sched_yield();// wait for a while
    sched_yield();
    sched_yield();
    sched_yield();
    sched_yield();
    sched_yield();
    sched_yield();
}

/*
 * the code for flushing an address from cache to memory
 * the input is a pointer
 */
static inline void flush(void *addr) {
    asm volatile("clflush 0(%0)": : "r" (addr):);
}


/*
 * the code for loading an address and timing the load
 * the output of this function is the time in CPU cycles
 * the input is a pointer
 */
static inline uint32_t memaccesstime(void *v) {
    uint32_t rv;
    asm volatile("mfence\n"
                 "lfence\n"
                 "rdtscp\n"
                 "mov %%eax, %%esi\n"
                 "mov (%1), %%eax\n"
                 "rdtscp\n"
                 "sub %%esi, %%eax\n"
    : "=&a"(rv)
    : "r"(v)
    : "ecx", "edx", "esi");
    return rv;
}


#endif //PITT_ECE_2162_SPECTRE_HELPER_H
