#include <arpa/inet.h>
#include <ctype.h>
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
            "Usage: %s [-h] -i input.pcap -o output.pcap [-s src_mac] [-d dst_mac]\n"
            "Options:\n"
            "  -h\t\tShow this help message\n"
            "  -i FILE\tInput PCAP file (required)\n"
            "  -o FILE\tOutput PCAP file (required)\n"
            "  -s MAC\tSource MAC address (format: aa:bb:cc:dd:ee:ff)\n"
            "  -d MAC\tDestination MAC address (format: 00:11:22:33:44:55)\n",
            progname);
}

int get_mac_from_string(const char* str, uint8_t mac[ETH_ALEN])
{
    if (!str)
        return -1;

    if (strnlen(str, 18) != 17)
        return -1;

    for (int i = 2; i < 17; i += 3) {
        if (str[i] != ':')
            return -1;
    }

    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2)
            continue;

        if (!isxdigit(str[i]))
            return -1;
    }

    int result = sscanf(str,
                        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                        &mac[0],
                        &mac[1],
                        &mac[2],
                        &mac[3],
                        &mac[4],
                        &mac[5]);

    return (result == ETH_ALEN) ? 0 : -1;
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
    int custom_macs = 0;
    int opt;

    uint8_t dst_mac[ETH_ALEN] = {0};
    uint8_t src_mac[ETH_ALEN] = {0};

    while ((opt = getopt(argc, argv, "hi:o:d:s:")) != -1) {
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
        case 'd':
            if (get_mac_from_string(optarg, dst_mac) != 0) {
                fprintf(stderr, "Error: Invalid destination MAC format\n");
                return 1;
            }
            custom_macs |= 1;
            break;
        case 's':
            if (get_mac_from_string(optarg, src_mac) != 0) {
                fprintf(stderr, "Error: Invalid source MAC format\n");
                return 1;
            }
            custom_macs |= 2;
            break;
        case '?':
            print_usage(argv[0]);
            return 1;
        default:
            abort();
        }
    }

    if (custom_macs && custom_macs != 3) {
        fprintf(stderr, "Error: Both -d and -s must be specified\n");
        return 1;
    }

    if (!custom_macs) {
        gen_rand_mac_pair(dst_mac, src_mac);
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

    struct pcap_pkthdr* header = NULL;
    const uint8_t* packet_data = NULL;
    uint8_t* new_packet = NULL;

    size_t packet_count = 0;
    int res = 0;

    int snaplen = pcap_snapshot(input_handle);
    if (snaplen <= 0) {
        fprintf(stderr, "Error: Invalid snaplen (%d)\n", snaplen);
        goto close;
    }

    new_packet = malloc(snaplen + sizeof(struct ethhdr));

    if (new_packet == NULL) {
        fprintf(stderr,
                "Error: Failed to allocate %zu bytes for packet #%zu\n",
                (size_t) (sizeof(struct ethhdr) + header->caplen),
                packet_count);
        goto close;
    }

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
                    "Error: Invalid packet #%zu (caplen %u > len %u)\n",
                    packet_count,
                    header->caplen,
                    header->len);
            continue;
        }

        if (header->caplen > 0xFFFF) {
            fprintf(stderr,
                    "Error: Packet #%zu exceeds max size (%u bytes)\n",
                    packet_count,
                    header->caplen);
            continue;
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
                continue;
            }
            eth_type = htons(ETH_P_IPV6);
            break;
        default:
            fprintf(stderr,
                    "Warning: Unknown IP version (%d) in packet #%zu, skipping\n",
                    packet_data[0] >> 4,
                    packet_count);
            continue;
        }

        memcpy(new_packet, dst_mac, ETH_ALEN);
        memcpy(new_packet + ETH_ALEN, src_mac, ETH_ALEN);
        memcpy(new_packet + 12, &eth_type, 2);

        memcpy(new_packet + sizeof(struct ethhdr), packet_data, header->caplen);

        struct pcap_pkthdr new_header = *header;
        new_header.caplen += sizeof(struct ethhdr);
        new_header.len += sizeof(struct ethhdr);

        pcap_dump((uint8_t*) output_dumper, &new_header, new_packet);
    }

    if (res == -1) {
        fprintf(stderr,
                "Error reading packet #%zu: %s\n",
                packet_count + 1,
                pcap_geterr(input_handle));
    }

close:
    if (new_packet)
        free(new_packet);

    pcap_dump_close(output_dumper);
    pcap_close(output_dead_handle);
    pcap_close(input_handle);

    return 0;
}
