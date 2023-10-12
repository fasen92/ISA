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
 * @brief 
 * 
 */
typedef struct {
  ipPrefix **prefixes;
  uint32_t *ipTaken;
  int *taken;
} Configuration;

ipPrefix* getArgs(int argc, char *argv[], char *interF, char *file, int *interSet, ipPrefix* prefixes);

void freeMem();

void handlePacket(u_char *user, const struct pcap_pkthdr *header, const unsigned char *packet);

void catch_end(int sig_num);

uint32_t* allocateArr(ipPrefix *prefixes);

void addAddr(uint32_t** arr, uint32_t addr, int *taken, ipPrefix *prefixes);

int subnetCheck(uint32_t yiaddr, ipPrefix prefix);

uint32_t* packet_handle(ipPrefix *prefixes, uint32_t *ipTaken, int *taken, const unsigned char **packet_data);

void printPrefixes(ipPrefix *prefixes, int refresh);

#endif /* DHCPSTATS_H */