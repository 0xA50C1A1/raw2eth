#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ETHERNET_HEADER_SIZE 14

void gen_rand_mac_pair(uint8_t dst_mac[6], uint8_t src_mac[6])
{
    /* First byte: 0x02 = Locally administered, unicast */
    dst_mac[0] = 0x02;
    src_mac[0] = 0x02;

    for (int i = 1; i < 6; i++) {
        dst_mac[i] = rand() & 0xFF;
        src_mac[i] = rand() & 0xFF;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.pcap> <output.pcap>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));

    const char* input_filename = argv[1];
    const char* output_filename = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* input_handle = pcap_open_offline(input_filename, errbuf);

    if (input_handle == NULL) {
        fprintf(stderr, "Couldn't open PCAP file %s: %s\n", input_filename, errbuf);
        return 1;
    }

    int datalink = pcap_datalink(input_handle);

    if (datalink != DLT_RAW && datalink != DLT_IPV4 && datalink != DLT_IPV6) {
        fprintf(stderr, "The link-layer header type is not DLT_RAW/DLT_IPV4/DLT_IPV6.");
        pcap_close(input_handle);
        return 1;
    }

    pcap_t* output_dead_handle = pcap_open_dead(DLT_EN10MB, 65535);

    if (output_dead_handle == NULL) {
        fprintf(stderr, "Failed to create dead handle for the output file.\n");
        pcap_close(input_handle);
        return 1;
    }

    pcap_dumper_t* output_dumper = pcap_dump_open(output_dead_handle, output_filename);

    if (output_dumper == NULL) {
        fprintf(stderr,
                "Failed to open file for writing %s: %s\n",
                output_filename,
                pcap_geterr(output_dead_handle));
        pcap_close(input_handle);
        pcap_close(output_dead_handle);
        return 1;
    }

    uint8_t dst_mac[6];
    uint8_t src_mac[6];

    gen_rand_mac_pair(dst_mac, src_mac);

    struct pcap_pkthdr* header = NULL;
    const uint8_t* packet_data = NULL;
    int res = 0;

    while ((res = pcap_next_ex(input_handle, &header, &packet_data)) >= 0) {
        if (res == 0)
            continue;

        uint8_t* new_packet = (uint8_t*) malloc(ETHERNET_HEADER_SIZE + header->caplen);

        if (new_packet == NULL) {
            fprintf(stderr, "Memory allocation error.\n");
            break;
        }

        uint16_t eth_type = 0;

        /* IP version */
        /* With DLT_IPV4 we should have only ipv4 (and only ipv6 with DLT_IPV6)
	 * but it should be harmless to check anyway */
        switch (packet_data[0] >> 4) {
        case 4:
            eth_type = htons(0x0800);
            break;
        case 6:
            eth_type = htons(0x86DD);
            break;
        default:
            fprintf(stderr, "Malformed packet.\n");
            free(new_packet);
            goto close;
        }

        memcpy(new_packet, dst_mac, 6);
        memcpy(new_packet + 6, src_mac, 6);
        memcpy(new_packet + 12, &eth_type, 2);

        memcpy(new_packet + ETHERNET_HEADER_SIZE, packet_data, header->caplen);

        struct pcap_pkthdr new_header = *header;
        new_header.caplen += ETHERNET_HEADER_SIZE;
        new_header.len += ETHERNET_HEADER_SIZE;

        pcap_dump((uint8_t*) output_dumper, &new_header, new_packet);

        free(new_packet);
    }

    if (res == -1) {
        fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(input_handle));
    }

close:
    pcap_dump_close(output_dumper);
    pcap_close(output_dead_handle);
    pcap_close(input_handle);

    return 0;
}
