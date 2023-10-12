/**
 * @file ip-prefix.c
 * @author Ivan Mahút (xmahut01)
 * @brief 
 * @version 0.1
 * @date 2023-10-07
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ip-prefix.h"
#include "dhcp-stats.h"

static int takenArr = 0;
static int sizeArr = 2;

ipPrefix* allocatePrefixArray() {
    ipPrefix* prefixes = (ipPrefix*) malloc (2 * sizeof(ipPrefix));
    if (prefixes == NULL) {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        exit(1);
    }
    return prefixes;
}

void addPrefix(ipPrefix** prefixes, ipPrefix prefix) {
    if (sizeArr - 1 == takenArr) {
        sizeArr += 2; // Double the size of the array
        ipPrefix* newPrefixes = (ipPrefix*)realloc(*prefixes, sizeArr * sizeof(ipPrefix));
        if (newPrefixes == NULL) {
            fprintf(stderr, "ERROR: Realloc has failed\n");
            freePrefixArray(*prefixes);
            freeMem();
            exit(2);
        }
        *prefixes = newPrefixes;
    }
    
    (*prefixes)[takenArr] = prefix;
    takenArr++;
}

void freePrefixArray(ipPrefix* prefixes) {
    free(prefixes);
}

uint32_t convertIP(char *ipStr){
    uint32_t ipInt = 0;
    char *ipToken;

    // tokenize string based on the period '.' separator
    ipToken = strtok(ipStr, ".");

    // each token represents one octet
    // convert each octet to an integer
    for (int i = 0; i < 4; i++) {
        int octet = atoi(ipToken);
        
        // shift 8 bits each time to get 32bit number
        ipInt = (ipInt << 8) | octet;
        
        // next token
        ipToken = strtok(NULL, ".");
        
        if (ipToken == NULL && i < 3) {
            fprintf(stderr, "ERROR: Invalid IP address\n");
            exit(3);
        }
    }

    return ipInt;
}

int getTaken(){
    return takenArr;
}
