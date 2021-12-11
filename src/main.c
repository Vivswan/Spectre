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
    int N = 1000;
    int a[N];
    int time_flush[N];
    int time_unflush[N];
    for (int i = 0; i < N; i++)
        a[i] = i;

    /*
     * in each iteration, flush, wait, and then reload and time the reload
     */
    for (int i = 0; i < N; i++) {
        flush(&(a[i]));
        wait();
        time_flush[i] = (int) memaccesstime(&(a[i]));

        wait();
        time_unflush[i] = (int) memaccesstime(&(a[i]));

        printf("(flushed, did not flush): (%d, %d)\n", time_flush[i], time_unflush[i]);
    }

}
