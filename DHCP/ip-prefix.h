/**
 * @file ip-prefix.h
 * @author Ivan Mahút (xmahut01)
 * @brief 
 * @version 0.1
 * @date 2023-10-07
 * 
 * @copyright Copyright (c) 2023
 * 
 */
#ifndef IPPREFIX_H
#define IPPREFIX_H

/**
 * @brief Struct contains data of 1 prefix
 * 
 */
typedef struct IpPrefix {
    char prefix[18];
    int mask;
    int slotsMax;
    int slotsTaken;
    uint32_t prefixBin;
} ipPrefix;

ipPrefix* allocatePrefixArray();

void addPrefix(ipPrefix** array, ipPrefix prefix);

void freePrefixArray(ipPrefix* array);

uint32_t convertIP(char *ipStr);

int getTaken();

#endif /* IPPREFIX_H */


