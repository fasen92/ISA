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
#include "ip-prefix.h"

pcap_t *sniffHandle;
char *interF;
char *file;
char *compFilter;

void freeMem(){
    free(interF);
    free(file);
    free(compFilter);
}

void handlePacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    printf("hehe\n");
    uint8_t opcode = packet[240];

    // Check if it's a DHCP ACK (opcode 2)
    if (12) {
        // Extract yiaddr (assigned IP address)
        uint32_t yiaddr[4];
        for (int i = 0; i < 4; i++) {
            yiaddr[i] = packet[18 + 20 + 8 + 16];
        }
        printf("DHCP ACK - Assigned IP address: %d.%d.%d.%d\n", yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]);
    }
}

void getArgs(int argc, char *argv[], char *interF, char *file, int *interSet, ipPrefix* prefixes){
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
            newPrefix.slotsMax = (2 ^ (32 - newPrefix.mask)) - 2;
            newPrefix.slotsTaken = 0;
            
            // get rid of last 3 chars to get only IP address 
            argv[i][strlen(argv[i])-3] = '\0';

            newPrefix.prefixBin = convertIP(argv[i]);

            addPrefix(prefixes, newPrefix);
            
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
}

int main(int argc, char *argv[])
{
    int numP = 2, interSet = 0;
    interF = malloc(40 * sizeof(char));
    if (interF == NULL)
    {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        exit(1);
    }
    file = malloc(100 * sizeof(char));
    if (file == NULL)
    {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        freeMem();
        exit(1);
    }
    compFilter = malloc(50 * sizeof(char));
    if (compFilter == NULL)
    {
        fprintf(stderr, "ERROR: Malloc has failed\n");
        freeMem();
        exit(1);
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    // struct sigaction sig;
    // sig.sa_handler = catch_end;
    // sigaction(SIGINT, &sig, NULL);
    ipPrefix *prefixes = allocatePrefixArray();

    getArgs(argc, argv, interF, file, &interSet, prefixes);

    if (interSet == 1)
    {
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;

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

        if(numP == 0) numP = 1;
        if(pcap_loop(sniffHandle, -1, handlePacket, NULL) == -1){
            pcap_close(sniffHandle);
            freeMem();
            freePrefixArray(prefixes);
            fprintf(stderr, "ERROR: Capturing of packets failed\n");
            exit(25);
        }

        pcap_close(sniffHandle);
        freeMem();
        freePrefixArray(prefixes);
        exit(0);

    }else{
        sniffHandle = pcap_open_offline(file, errbuf);

        if (sniffHandle == NULL) {
            fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
            freeMem();
            freePrefixArray(prefixes);
            exit(26);
        }

        struct pcap_pkthdr header;
        const unsigned char *packet_data;

        while (pcap_next_ex(sniffHandle, &header, &packet_data) >= 0) {
            printf("Packet length: %u\n", header.len);
        }

        pcap_close(sniffHandle);
        freeMem();
        freePrefixArray(prefixes);
        exit(0);
    }
}
