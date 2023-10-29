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
    char prefix[18]; // prefix in string for printing
    int mask; 
    int slotsMax;
    int slotsTaken;
    uint32_t prefixBin; // ip address of prefix in binary form
} ipPrefix;

/**
 * @brief Allocates memory for 2 structs
 * 
 * @return ipPrefix* pointer to allocated memory
 */
ipPrefix* allocatePrefixArray();

/**
 * @brief Function adds prefix to array, reallocates memory if necessary
 * 
 * @param array pointer to array of structs
 * @param prefix struct to be added
 */
void addPrefix(ipPrefix** array, ipPrefix prefix);

/**
 * @brief Frees memory
 * 
 * @param array pointer to array
 */
void freePrefixArray(ipPrefix* array);

/**
 * @brief Converts ip address from string to binary form
 * 
 * @param ipStr IP address in string
 * @return uint32_t IP address in binary
 */
uint32_t convertIP(char *ipStr);

/**
 * @brief Returns number of taken slots in allocated array
 * 
 * @return int 
 */
int getTaken();

#endif /* IPPREFIX_H */


