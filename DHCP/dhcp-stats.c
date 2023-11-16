/**
 * @file dhcp-stats.c
 * @author Ivan Mahút (xmahut01)
 * @brief
 * @version 0.1
 * @date 2023-10-06
 *
 * @copyright Copyright (c) 2023
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include <regex.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <ncurses.h>
#include <math.h>
#include <syslog.h>
#include "ip-prefix.h"
#include "dhcp-stats.h"

pcap_t *sniffHandle;
char *interF;
char *file;
char *compFilter;
uint32_t *ipTaken;
static int sizeArr = 2;

int main(int argc, char *argv[])
{
    int interSet = 0;
    int taken = 0;
    interF = malloc(40);
    if (interF == NULL)
    {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        exit(1);
    }
    file = malloc(100);
    if (file == NULL)
    {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        freeMem();
        exit(1);
    }
    compFilter = malloc(50);
    if (compFilter == NULL)
    {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        freeMem();
        exit(1);
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    struct sigaction sig = {.sa_handler = catch_end};
    sigaction(SIGINT, &sig, NULL);
    ipPrefix *prefixes = allocatePrefixArray();
    ipTaken = allocateArr(prefixes);

    prefixes = getArgs(argc, argv, interF, file, &interSet, prefixes);
    
    initscr(); 
    printHeader();
    
    for (int i = 0; i < getTaken(); i++) {
        printPrefix(&prefixes[i]);
    }

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    struct pcap_pkthdr *header;
    const unsigned char *packet_data;

    if (interSet == 1)
    {
        // getting netmask of int
        if (pcap_lookupnet(interF, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "ERROR : Netmask couldn't be optained\n");
            net = 0;
            mask = 0;
        }

        // opening int for sniffing
        sniffHandle = pcap_open_live(interF, BUFSIZ, 0, 1000, errbuf);
        if (sniffHandle == NULL)
        {
            fprintf(stderr, "ERROR: Interface cannot be openned %s\n", errbuf);
            freeMem();
            freePrefixArray(prefixes);
            exit(22);
        }

        strcpy(compFilter, "dst port 68 or vlan");

        // compiling filter
        if (pcap_compile(sniffHandle, &fp, compFilter, 0, net) == -1)
        {
            fprintf(stderr, "ERROR: Couldn't parse filter %s : %s\n", compFilter, pcap_geterr(sniffHandle));
            free(interF);
            free(compFilter);
            exit(23);
        }

        // setting filter
        if (pcap_setfilter(sniffHandle, &fp) == -1)
        {
            fprintf(stderr, "ERROR: Couldn't install filter %s: %s\n", compFilter, pcap_geterr(sniffHandle));
            freeMem();
            freePrefixArray(prefixes);
            exit(24);
        }

        // Sniffing of packets
        while (pcap_next_ex(sniffHandle, &header, &packet_data) >= 0)
        {
            ipTaken = packet_handle(prefixes, ipTaken, &taken, &header, &packet_data);
        }
    }
    else
    {
        sniffHandle = pcap_open_offline(file, errbuf); // Opening file as handle

        if (sniffHandle == NULL)
        {
            fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
            freeMem();
            freePrefixArray(prefixes);
            exit(25);
        }

        strcpy(compFilter, "dst port 68 or vlan");

        // Compiling filter
        if (pcap_compile(sniffHandle, &fp, compFilter, 0, net) == -1)
        {
            fprintf(stderr, "ERROR: Couldn't parse filter %s : %s\n", compFilter, pcap_geterr(sniffHandle));
            free(interF);
            free(compFilter);
            exit(23);
        }

        // Setting filter
        if (pcap_setfilter(sniffHandle, &fp) == -1)
        {
            fprintf(stderr, "ERROR: Couldn't install filter %s: %s\n", compFilter, pcap_geterr(sniffHandle));
            freeMem();
            freePrefixArray(prefixes);
            exit(24);
        }

        while (pcap_next_ex(sniffHandle, &header, &packet_data) >= 0)
        {
            ipTaken = packet_handle(prefixes, ipTaken, &taken, &header, &packet_data);
        }
    }

    getch(); // Wait for a key before clearing terminal
    endwin(); // Close ncurces
    pcap_close(sniffHandle);
    freeMem();
    freePrefixArray(prefixes);
    exit(0);
}

void freeMem()
{
    free(interF);
    free(file);
    free(compFilter);
    free(ipTaken);
}

uint32_t *packet_handle(ipPrefix *prefixes, uint32_t *ipTaken, int *taken, struct pcap_pkthdr **header, const unsigned char **packetData)
{
    int isSubnet = 0;
    uint8_t opcode = 0;
    const uint8_t *dhcpPacket;
    const unsigned char *data = *packetData;
    if ((*header)->caplen >= 14 + 4)
    {
        // At least 14 bytes for the Ethernet header and 4 bytes for the VLAN tag
        uint16_t ethertype = ((*packetData)[12] << 8) | (*packetData)[13];
        if (ethertype == 0x8100)
        { // VLAN packet
            if ((*header)->caplen >= 14 + 4 + 20 + 8 + 4)
            {
                // Ensure sufficient length for VLAN tag, IP header, UDP header, and DHCP opcode
                opcode = (*packetData)[14 + 20 + 8 + 4];
                dhcpPacket = data +14 + 20 + 8 + 4;
            }
        }
        else
        {
            // Non-VLAN packet
            if ((*header)->caplen >= 14 + 20 + 8)
            {
                // Ensure sufficient length for Ether header, IP header, UDP header, and DHCP opcode
                opcode = (*packetData)[14 + 20 + 8];
                dhcpPacket = data + 14 + 20 + 8;
            }
        }
    }

    // Check if it's a DHCP ACK
    if (opcode == 2)
    {
        const uint8_t *dhcpOptions = dhcpPacket + 240;
        uint8_t optionCode;
        uint8_t lenghtOP = 0;

        for (; (*dhcpOptions) != 255; dhcpOptions += lenghtOP)
        {
            optionCode = *dhcpOptions++;
            lenghtOP = *dhcpOptions++;

            if (optionCode == 53 && lenghtOP == 1 && *(dhcpOptions) == 5)
            { // Check for DHCP ACK
                uint32_t yiaddr = 0;

                // yiaddr starts at 17th byte of DHCP packet (pointer to DHCP packet + 16)
                for (int i = 0; i < 4; i++)
                {
                    yiaddr = (yiaddr << 8) | dhcpPacket[16 + i]; // convert to binary form
                }

                // If IP address is in array, it has been already counted
                for (int i = 0; i < (*taken); i++)
                {
                    if (ipTaken[i] == yiaddr)
                    {
                        return ipTaken;
                    }
                }

                // Cycle through prefixes to check whether ip matches
                for (int i = 0; i < getTaken(); i++)
                {
                    if (subnetCheck(yiaddr, prefixes[i]))
                    {
                        prefixes[i].slotsTaken++;
                        isSubnet = 1;
                        updatePrefix(&prefixes[i],i+1);
                    }
                }

                if (isSubnet)
                {
                    addAddr(&ipTaken, yiaddr, taken, prefixes); // Adding addr to array
                }

                break;
            }
        }
    }

    return ipTaken; // Returning pointer, because realloc might have changed it
}

ipPrefix *getArgs(int argc, char *argv[], char *interF, char *file, int *interSet, ipPrefix *prefixes)
{
    char *pattern = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\/([0-9]|[1-2][0-9]|3[0-2])$";
    char *short_options = "r:i:";
    int fileSet = 0;
    regex_t regex;

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0)
    {
        fprintf(stderr, "Failed to compile regex\n");
        freeMem();
        freePrefixArray(prefixes);
        exit(4);
    }

    char arg;

    while ((arg = getopt(argc, argv, short_options)) != -1)
    {
        switch (arg)
        {
        case 'i':
            if (optarg == NULL)
            {
                if (optind != argc)
                {
                    *(interSet) = 1;
                    strcpy(interF, argv[optind]);
                    optind++; // set optind to next position
                }
            }
            else
            {
                *(interSet) = 1;
                strcpy(interF, optarg);
            }
            break;
        case 'r':
            if (optarg == NULL)
            {
                if (optind != argc)
                {
                    fileSet = 1;
                    strcpy(file, argv[optind]);
                    optind++; // set optind to next position
                }
            }
            else
            {
                fileSet = 1;
                strcpy(file, optarg);
            }
            break;
        case '?':
            fprintf(stderr, "ERROR: Unknown parameter\n\tUsage: [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n");
            freeMem();
            exit(10);
        default:
            break;
        }
    }

    for (int i = optind; i < argc; i++)
    {
        int match = regexec(&regex, argv[i], 0, NULL, 0);
        if (match == 0)
        {
            ipPrefix newPrefix;
            // Save prefix for printing
            strcpy(newPrefix.prefix, argv[i]);

            // Get last 2 chars from prefix
            char mask[3];
            int prefixLen = strlen(argv[i]);
            mask[0] = argv[i][prefixLen - 2];
            mask[1] = argv[i][prefixLen - 1];
            mask[2] = '\0';

            // Convert them to the number
            newPrefix.mask = atoi(mask);

            // Calculate number of possible hosts
            newPrefix.slotsMax = (int)(pow(2, 32 - newPrefix.mask) - (double)2);
            newPrefix.slotsTaken = 0;

            // Get rid of last 3 chars to get only IP address
            argv[i][strlen(argv[i]) - 3] = '\0';

            newPrefix.prefixBin = convertIP(argv[i]);

            addPrefix(&prefixes, newPrefix);
        }
        else if (match == REG_NOMATCH)
        {
            fprintf(stderr, "ERROR: Invalid IP prefix: %s\n", argv[i]);
            freeMem();
            freePrefixArray(prefixes);
            exit(11);
        }
        else
        {
            char error_message[100];
            regerror(match, &regex, error_message, sizeof(error_message));
            fprintf(stderr, "ERROR: Regex match failed: %s\n", error_message);
            freeMem();
            freePrefixArray(prefixes);
            exit(12);
        }
    }

    // interface and file cannot be used at the same time
    if (*(interSet) == fileSet)
    {
        if (fileSet == 1)
        {
            fprintf(stderr, "ERROR: Too many arguments\n\tUse -r <filename> or -i <interface>\n");
        }
        else
        {
            fprintf(stderr, "ERROR: Too few arguments\n\tUse -r <filename> or -i <interface>\n");
        }
        freeMem();
        freePrefixArray(prefixes);
        exit(10);
    }

    regfree(&regex); // free regex struct
    return prefixes;
}

int subnetCheck(uint32_t yiaddr, ipPrefix prefix)
{
    uint32_t prefMask = 0xFFFFFFFF << (32 - prefix.mask); // Calculate mask in bits
    uint32_t broadcast = prefix.prefixBin | ~prefMask;    // Calculate broadcast address of prefix
    if (yiaddr == prefix.prefixBin || yiaddr == broadcast)
    { // Host cannot be prefix or broadcast address
        return 0;
    }
    return (yiaddr & prefMask) == (prefix.prefixBin & prefMask); // If equal => address belongs to the prefix
}

void catch_end(int sig_num)
{
    (void)sig_num;               // To get rid of warning
    pcap_breakloop(sniffHandle); // Stop sniffing
}

uint32_t *allocateArr(ipPrefix *prefixes)
{
    uint32_t *arr = (uint32_t *)malloc(2 * sizeof(uint32_t)); // allocate array of 2 uint_32
    if (arr == NULL)
    {
        endwin();
        freeMem();
        freePrefixArray(prefixes);
        exit(1);
    }
    return arr;
}

void addAddr(uint32_t **arr, uint32_t addr, int *taken, ipPrefix *prefixes)
{
    if (sizeArr - 1 == (*taken))
    {
        sizeArr *= 2; // Double the size of the array
        uint32_t *newArr = (uint32_t *)realloc(*arr, sizeArr * sizeof(uint32_t));
        if (arr == NULL)
        {
            fprintf(stderr, "ERROR: Realloc has failed\n");
            freePrefixArray(prefixes);
            freeMem();
            exit(2);
        }
        *arr = newArr;
    }
    (*arr)[(*taken)] = addr; // Assign address to array
    (*taken)++;              // Increment number of taken addresses
}

void printHeader() {
    printw("%-20s%-12s%-22s%s\n", "IP-Prefix", "Max-hosts", "Allocated addresses", "Utilization");
}

void printPrefix(ipPrefix *prefix) {
    printw("%-20s%-12d%-22d%.2f%%\n", prefix->prefix, prefix->slotsMax,
           prefix->slotsTaken, 0.0);
}

void updatePrefix(ipPrefix *prefix, int position) {
    float utilization = ((float)prefix->slotsTaken / prefix->slotsMax) * 100; // calculate utilization
    move(position, 0); // Move cursor to the line where prefix information starts
    if(utilization < 50.0){
        printw("\r%-20s%-12d%-22d%.2f%%", prefix->prefix, prefix->slotsMax, prefix->slotsTaken,utilization );
    }else{
        printw("\r%-20s%-12d%-22d%.2f%%\t- 50%% has been exceede -", prefix->prefix, prefix->slotsMax, prefix->slotsTaken,utilization );
        
        openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1); // opening log file

        syslog(LOG_NOTICE, "Prefix %s exceeded 50%% of allocations ", prefix->prefix);

        closelog();
    }
    refresh();
}