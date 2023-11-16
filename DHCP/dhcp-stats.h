/**
 * @file dhcp-stats.h
 * @author Ivan Mahút (xmahut01)
 * @brief 
 * @version 0.1
 * @date 2023-10-12
 * 
 * @copyright Copyright (c) 2023
 * 
 */
#ifndef DHCPSTATS_H
#define DHCPSTATS_H

/**
 * @brief Functions validates and process arguments
 * 
 * @param argc count of argumente
 * @param argv arguments
 * @param interF interface name from arguments
 * @param file file name from arguments
 * @param interSet flag indicates if interface was set (or file)
 * @param prefixes pointer to array of structs to save prefixes from parameters
 * @return ipPrefix* 
 */
ipPrefix* getArgs(int argc, char *argv[], char *interF, char *file, int *interSet, ipPrefix* prefixes);

/**
 * @brief Function frees alocated memory
 * 
 */
void freeMem();

/**
 * @brief Ctrl+c handler
 * 
 * @param sig_num
 */
void catch_end(int sig_num);

/**
 * @brief Function allocates memory to store processed IP adresses
 * 
 * @param prefixes pointer to array of structs
 * @return uint32_t* pointer to allocated memory
 */
uint32_t* allocateArr(ipPrefix *prefixes);

/**
 * @brief Adds address to array, reallocates if necessary
 * 
 * @param arr pointer to array
 * @param addr IP address to be added to array
 * @param taken number of taken IP addresses
 * @param prefixes array of structs
 */
void addAddr(uint32_t** arr, uint32_t addr, int *taken, ipPrefix *prefixes);

/**
 * @brief Checks if address is valid host of prefix
 * 
 * @param yiaddr IP address to be checked
 * @param prefix single prefix struct 
 * @return int 1 -> address belongs to the prefix
 */
int subnetCheck(uint32_t yiaddr, ipPrefix prefix);

/**
 * @brief Dunction to process filtered packets
 * 
 * @param prefixes array of structs
 * @param ipTaken array of taken IP addresses
 * @param taken number of taken IP addresses
 * @param packet_data content of packet
 * @return uint32_t* returns pointer to ipTaken, because realloc may have changed it
 */
uint32_t* packet_handle(ipPrefix *prefixes, uint32_t *ipTaken, int *taken, struct pcap_pkthdr **header, const unsigned char **packetData);

/**
 * @brief prints header of stats
 * 
 */
void printHeader();

/**
 * @brief prints default stats of given prefix
 * 
 * @param prefix 
 */
void printPrefix(ipPrefix *prefix);

/**
 * @brief updates prefix with new values
 * 
 * @param prefix 
 * @param position position of prefix to be updated
 */
void updatePrefix(ipPrefix *prefix, int position);

#endif /* DHCPSTATS_H */