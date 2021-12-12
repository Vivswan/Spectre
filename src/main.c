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
#include "pthread.h"
#include "unistd.h"
#include "inttypes.h"

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


int main() {
    int cacheHitThresholdTime = getCacheHitThresholdTime(10000);
    printf("Cache Hit Threshold Time : %d\n", cacheHitThresholdTime);
}
