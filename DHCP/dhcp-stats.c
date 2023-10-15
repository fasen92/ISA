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
    int taken= 0;
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

    Configuration conf[1] = {{&prefixes, ipTaken, &taken}};   

    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;


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
        
        strcpy(compFilter, "dst port 68");

        // compiling filter
        if(pcap_compile(sniffHandle, &fp, compFilter, 0, net) == -1){
            fprintf(stderr, "ERROR: Couldn't parse filter %s : %s\n", compFilter, pcap_geterr(sniffHandle));
            free(interF);
            free(compFilter);
            exit(23);
        }

        // setting filter
        if(pcap_setfilter(sniffHandle, &fp) == -1){
            fprintf(stderr, "ERROR: Couldn't install filter %s: %s\n", compFilter, pcap_geterr(sniffHandle));
            freeMem();
            freePrefixArray(prefixes);
            exit(24);
        }

        struct pcap_pkthdr *header;
        const unsigned char *packet_data;

        printPrefixes(prefixes, 1); 

        while (pcap_next_ex(sniffHandle, &header, &packet_data) >= 0) {
            ipTaken = packet_handle(prefixes, ipTaken, &taken, &packet_data);
        }

    }else{
        sniffHandle = pcap_open_offline(file, errbuf);

        if (sniffHandle == NULL) {
            fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
            freeMem();
            freePrefixArray(prefixes);
            exit(26);
        }

        strcpy(compFilter, "dst port 68");

        // compiling filter
        if(pcap_compile(sniffHandle, &fp, compFilter, 0, net) == -1){
            fprintf(stderr, "ERROR: Couldn't parse filter %s : %s\n", compFilter, pcap_geterr(sniffHandle));
            free(interF);
            free(compFilter);
            exit(23);
        }

        // setting filter
        if(pcap_setfilter(sniffHandle, &fp) == -1){
            fprintf(stderr, "ERROR: Couldn't install filter %s: %s\n", compFilter, pcap_geterr(sniffHandle));
            freeMem();
            freePrefixArray(prefixes);
            exit(24);
        }

        struct pcap_pkthdr *header;
        const unsigned char *packet_data;

        printPrefixes(prefixes, 1); 

        while (pcap_next_ex(sniffHandle, &header, &packet_data) >= 0) {
            ipTaken = packet_handle(prefixes, ipTaken, &taken, &packet_data);
        }

        // wait for a key before clearing terminal
        printPrefixes(prefixes,-1);
    }

    endwin();
    pcap_close(sniffHandle);
    freeMem();
    freePrefixArray(prefixes);
    exit(0);
}

void freeMem(){
    free(interF);
    free(file);
    free(compFilter);
    free(ipTaken);
}

uint32_t* packet_handle(ipPrefix *prefixes, uint32_t *ipTaken, int *taken, const unsigned char **packet_data){
    int isSubnet = 0;
    uint8_t opcode = (*packet_data)[14+20+8]; // ether header + ip header + udp header -> DHCP packet (first 8bits is opcode)

    // check if it's a DHCP ACK 
    if (opcode == 2) {
        // extract yiaddr
        uint32_t yiaddr = 0 ;
        
        // yiaddr starts at 17th byte of DHCP packet (pointer to DHCP packet + 16)
        for (int i = 0; i < 4; i++) {
            yiaddr = (yiaddr << 8) | (*packet_data)[14 + 20 + 8 + 16 + i];
        }

        for(int i = 0; i < (*taken); i++){
            if(ipTaken[i] == yiaddr){
                return ipTaken;
            }
        }

        for(int i = 0; i < getTaken(); i++){
            if(subnetCheck(yiaddr,prefixes[i])){
                prefixes[i].slotsTaken++;
                isSubnet = 1;
                printPrefixes(prefixes,0);
            }
        }

        if(isSubnet){
            addAddr(&ipTaken, yiaddr, taken, prefixes);
        }
    }

    return ipTaken;
}

ipPrefix* getArgs(int argc, char *argv[], char *interF, char *file, int *interSet, ipPrefix* prefixes){
    char* pattern = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\/([0-9]|[1-2][0-9]|3[0-2])$";
    char *short_options = "r:i:";
    int fileSet = 0;
    regex_t regex;

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
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
                if (optarg == NULL) {
                    if (optind != argc) {
                        *(interSet) = 1;
                        strcpy(interF,argv[optind]);
                        optind++;  // set optind to next position
                    }
                }else {
                    *(interSet) = 1;
                    strcpy(interF,optarg);
                }
                break;
            case 'r':
                if (optarg == NULL) {
                    if (optind != argc) {
                        fileSet = 1;
                        strcpy(file,argv[optind]);
                        optind++;  // set optind to next position
                    }
                }else {
                    fileSet = 1;
                    strcpy(file,optarg);
                }
                break;
            case '?':
                //printf("%s",argv[optind]);
                fprintf(stderr,"ERROR: Unknown parameter\n\tUsage: [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n");
                freeMem();
                exit(10);
            default:
                break;
        }
    }

    for (int i = optind; i < argc; i++) {
        int match = regexec(&regex, argv[i], 0, NULL, 0);
        if (match == 0) {
            ipPrefix newPrefix;
            // save prefix for printing
            strcpy(newPrefix.prefix,argv[i]);
            
            // get last 2 chars from prefix
            char mask[3];
            int prefixLen = strlen(argv[i]);
            mask[0] = argv[i][prefixLen - 2];
            mask[1] = argv[i][prefixLen - 1];
            mask[2] = '\0';

            // convert them to the number
            newPrefix.mask = atoi(mask);

            // calculate number of possible hosts
            newPrefix.slotsMax = (int) (pow(2, 32 - newPrefix.mask) - (double)2);
            newPrefix.slotsTaken = 0;
            
            // get rid of last 3 chars to get only IP address 
            argv[i][strlen(argv[i])-3] = '\0';

            newPrefix.prefixBin = convertIP(argv[i]);
            //printf("%s -- %d -- %d -- %d --\n",newPrefix.prefix, newPrefix.mask, newPrefix.slotsMax, newPrefix.slotsTaken);

            addPrefix(&prefixes, newPrefix);
            
        } else if (match == REG_NOMATCH) {
            fprintf(stderr,"ERROR: Invalid IP prefix: %s\n", argv[i]);
            freeMem();
            freePrefixArray(prefixes);
            exit(11);
        } else {
            char error_message[100];
            regerror(match, &regex, error_message, sizeof(error_message));
            fprintf(stderr, "ERROR: Regex match failed: %s\n", error_message);
            freeMem();
            freePrefixArray(prefixes);
            exit(12);
        }
    }

    if(*(interSet) == fileSet){
        if(fileSet == 1){
            fprintf(stderr,"ERROR: Too many arguments\n\tUse -r <filename> or -i <interface>\n");
            
        }else{
            fprintf(stderr,"ERROR: Too few arguments\n\tUse -r <filename> or -i <interface>\n");
        }
        freeMem();
        freePrefixArray(prefixes);
        exit(10);
    }
    
    regfree(&regex);
    return prefixes;
}

int subnetCheck(uint32_t yiaddr, ipPrefix prefix) {
    uint32_t prefMask = 0xFFFFFFFF << (32 - prefix.mask);
    uint32_t broadcast = prefix.prefixBin | ~prefMask;
    if(yiaddr == prefix.prefixBin || yiaddr == broadcast){
        return 0;
    }
    return (yiaddr & prefMask) == (prefix.prefixBin & prefMask);
}

void catch_end(int sig_num)
{
    (void)sig_num; // to get rid of warning
    pcap_breakloop(sniffHandle);
}


uint32_t* allocateArr(ipPrefix *prefixes) {
    uint32_t* arr = (u_int32_t*)malloc(2 * sizeof(uint32_t));
    if (arr == NULL) {
        freeMem();
        freePrefixArray(prefixes);
        exit(1);
    }
    return arr;
}

void addAddr(uint32_t** arr, uint32_t addr, int *taken, ipPrefix *prefixes) {
    //printf("%d -- %d\n", sizeArr, (*taken));
    if (sizeArr - 1 == (*taken)) {
        sizeArr *= 2; // Double the size of the array
        uint32_t *newArr = (uint32_t*) realloc (*arr, sizeArr * sizeof(uint32_t));
        if (arr == NULL) {
            fprintf(stderr, "ERROR: Realloc has failed\n");
            freePrefixArray(prefixes);
            freeMem();
            exit(2);
        }
        *arr = newArr;
    }
    //printf("%d taken %u",(*taken),addr);
    (*arr)[(*taken)] = addr;
    (*taken)++;
}

void printPrefixes(ipPrefix *prefixes, int refresh) {
    initscr();  // Initialize ncurses
    cbreak();
    noecho();

    // Create a window for the table
    int numRows = getTaken() + 3;
    int numCols = 70;
    WINDOW *table = newwin(numRows, numCols, 1, 1);
    box(table, 0, 0);

    // Print table headers
    mvwprintw(table, 1, 2, "IP-Prefix");
    mvwprintw(table, 1, 20, "Max-hosts");
    mvwprintw(table, 1, 35, "Allocated addresses");
    mvwprintw(table, 1, 55, "Utilization");

    // Print data in the table
    for (int i = 0; i < getTaken(); i++) {
        mvwprintw(table, i + 2, 2, prefixes[i].prefix);
        mvwprintw(table, i + 2, 20, "%d", prefixes[i].slotsMax);
        mvwprintw(table, i + 2, 35, "%d", prefixes[i].slotsTaken);

        // Calculate utilization
        float utilization;
        if(prefixes[i].slotsTaken != 0){
            utilization = (float)prefixes[i].slotsTaken / prefixes[i].slotsMax * 100.0;
            if(utilization >= 50.0){
                openlog ("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

                syslog (LOG_NOTICE, "Prefix %s exceeded 50%% of allocations ", prefixes[i].prefix);

                closelog ();
            }
        }else{
            utilization = 0;
        }

        mvwprintw(table, i + 2, 55, "%.2f%%", utilization);
    }

    // Refresh the table
    wrefresh(table);
    if(refresh == -1){
        wgetch(table);
        endwin();
    }
}
