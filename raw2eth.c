#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void print_usage(const char* progname)
{
    fprintf(stderr,
            "Usage: %s [-h] -i input.pcap -o output.pcap\n"
            "Options:\n"
            "  -h\t\tShow this help message\n"
            "  -i FILE\tInput PCAP file (required)\n"
            "  -o FILE\tOutput PCAP file (required)\n",
            progname);
}

void gen_rand_mac_pair(uint8_t dst_mac[ETH_ALEN], uint8_t src_mac[ETH_ALEN])
{
    /* First byte: 0x02 = Locally administered, unicast */
    dst_mac[0] = 0x02;
    src_mac[0] = 0x02;

    for (int i = 1; i < ETH_ALEN; i++) {
        dst_mac[i] = rand() & 0xFF;
        src_mac[i] = rand() & 0xFF;
    }
}

int main(int argc, char* argv[])
{
    srand(time(NULL));

    const char* input_filename = NULL;
    const char* output_filename = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "hi:o:")) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case '?':
            print_usage(argv[0]);
            return 1;
        default:
            abort();
        }
    }

    if (!input_filename || !output_filename) {
        fprintf(stderr, "Error: Both input and output files must be specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* input_handle = pcap_open_offline(input_filename, errbuf);

    if (input_handle == NULL) {
        fprintf(stderr, "Error: Could not open input file '%s': %s\n", input_filename, errbuf);
        return 1;
    }

    int datalink = pcap_datalink(input_handle);

    if (datalink != DLT_RAW && datalink != DLT_IPV4 && datalink != DLT_IPV6) {
        fprintf(stderr,
                "Error: Input file has unsupported link-layer header type %d (%s)\n"
                "Supported types: DLT_RAW (%d), DLT_IPV4 (%d), DLT_IPV6 (%d)\n",
                datalink,
                pcap_datalink_val_to_name(datalink),
                DLT_RAW,
                DLT_IPV4,
                DLT_IPV6);
        pcap_close(input_handle);
        return 1;
    }

    pcap_t* output_dead_handle = pcap_open_dead(DLT_EN10MB, 0xFFFF);

    if (output_dead_handle == NULL) {
        fprintf(stderr,
                "Error: Could not create output file '%s': %s\n",
                output_filename,
                pcap_geterr(output_dead_handle));
        pcap_close(input_handle);
        return 1;
    }

    pcap_dumper_t* output_dumper = pcap_dump_open(output_dead_handle, output_filename);

    if (output_dumper == NULL) {
        fprintf(stderr,
                "Error: Could not create output file '%s': %s\n",
                output_filename,
                pcap_geterr(output_dead_handle));
        pcap_close(input_handle);
        pcap_close(output_dead_handle);
        return 1;
    }

    uint8_t dst_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];

    gen_rand_mac_pair(dst_mac, src_mac);

    struct pcap_pkthdr* header = NULL;
    const uint8_t* packet_data = NULL;

    size_t packet_count = 0;
    int res = 0;

    while ((res = pcap_next_ex(input_handle, &header, &packet_data)) >= 0) {
        if (res == 0)
            continue;

        packet_count++;

        if (header->caplen < 1) {
            fprintf(stderr,
                    "Error: Packet #%zu too small (%d bytes) to determine IP version\n",
                    packet_count,
                    header->caplen);
            continue;
        }

        if (header->caplen > header->len) {
            fprintf(stderr,
                    "Warning: Packet #%zu truncated (caplen %u > len %u)\n",
                    packet_count,
                    header->caplen,
                    header->len);
            header->len = header->caplen;
        }

        if (header->caplen > UINT32_MAX - sizeof(struct ethhdr)) {
            fprintf(stderr, "Error: Packet #%zu too large for Ethernet header\n", packet_count);
            continue;
        }

        if (header->caplen > 0xFFFF) {
            fprintf(stderr,
                    "Error: Packet #%zu exceeds max size (%u bytes)\n",
                    packet_count,
                    header->caplen);
            continue;
        }

        uint8_t* new_packet = (uint8_t*) malloc(sizeof(struct ethhdr) + header->caplen);

        if (new_packet == NULL) {
            fprintf(stderr,
                    "Error: Failed to allocate %zu bytes for packet #%zu\n",
                    (size_t) (sizeof(struct ethhdr) + header->caplen),
                    packet_count);
            goto close;
        }

        uint16_t eth_type = 0;

        /* IP version */
        /* With DLT_IPV4 we should have only ipv4 (and only ipv6 with DLT_IPV6)
	 * but it should be harmless to check anyway */
        switch (packet_data[0] >> 4) {
        case 4:
            if (header->caplen < sizeof(struct ip)) {
                fprintf(stderr,
                        "Error: Packet #%zu too small for IPv4 header (%d bytes)\n",
                        packet_count,
                        header->caplen);
                free(new_packet);
                new_packet = NULL;
                continue;
            }
            eth_type = htons(ETH_P_IP);
            break;
        case 6:
            if (header->caplen < sizeof(struct ip6_hdr)) {
                fprintf(stderr,
                        "Error: Packet #%zu too small for IPv6 header (%d bytes)\n",
                        packet_count,
                        header->caplen);
                free(new_packet);
                new_packet = NULL;
                continue;
            }
            eth_type = htons(ETH_P_IPV6);
            break;
        default:
            fprintf(stderr,
                    "Warning: Unknown IP version (%d) in packet #%zu, skipping\n",
                    packet_data[0] >> 4,
                    packet_count);
            free(new_packet);
            new_packet = NULL;
            continue;
        }

        memcpy(new_packet, dst_mac, 6);
        memcpy(new_packet + 6, src_mac, 6);
        memcpy(new_packet + 12, &eth_type, 2);

        memcpy(new_packet + sizeof(struct ethhdr), packet_data, header->caplen);

        struct pcap_pkthdr new_header = *header;
        new_header.caplen += sizeof(struct ethhdr);
        new_header.len += sizeof(struct ethhdr);

        pcap_dump((uint8_t*) output_dumper, &new_header, new_packet);

        free(new_packet);
        new_packet = NULL;
    }

    if (res == -1) {
        fprintf(stderr,
                "Error reading packet #%zu: %s\n",
                packet_count + 1,
                pcap_geterr(input_handle));
    }

close:
    pcap_dump_close(output_dumper);
    pcap_close(output_dead_handle);
    pcap_close(input_handle);

    return 0;
}
