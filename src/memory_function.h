#ifndef PITT_ECE_2162_SPECTRE_MEMORY_FUNCTION_H
#define PITT_ECE_2162_SPECTRE_MEMORY_FUNCTION_H

#include "sched.h"

/* wait for a while */
static inline void wait() {
    sched_yield();
    sched_yield();
    sched_yield();
//    sched_yield();
//    sched_yield();
//    sched_yield();
//    sched_yield();
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

static int getCacheHitThresholdTime(int N) {
    uint8_t a[N];
    int ramAccessTime[N], cacheAccessTime[N];
    int avgRamAccessTime, avgCacheAccessTime;
    for (int i = 0; i < N; i++) a[i] = 1;

    /*
     * in each iteration, flush, wait, and then reload and time the reload
     */
    for (int i = 0; i < N; i++) {
        flush(&(a[i]));
        wait();
        ramAccessTime[i] = (int) memaccesstime(&(a[i]));
        wait();
        cacheAccessTime[i] = (int) memaccesstime(&(a[i]));
        wait();
        avgRamAccessTime += ramAccessTime[i];
        avgCacheAccessTime += cacheAccessTime[i];
    }
    avgRamAccessTime /= N;
    avgCacheAccessTime /= N;

//    printf("Average RAM Access Time  : %d\n", avgRamAccessTime);
//    printf("Average Cache Access Time: %d\n", avgCacheAccessTime);

    return (avgRamAccessTime + avgCacheAccessTime) / 2;
}

#endif //PITT_ECE_2162_SPECTRE_MEMORY_FUNCTION_H
