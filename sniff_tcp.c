#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;

            printf("----------------------------------------\n");

            // Ethernet Header
            printf("Ethernet Header\n");
            printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP Header
            printf("IP Header\n");
            printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            // TCP Header
            printf("TCP Header\n");
            printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // HTTP 메시지 출력 (Payload)
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int total_len = ntohs(ip->iph_len);
            int payload_len = total_len - ip_header_len - tcp_header_len;

            if (payload_len > 0) {
                printf("Message (ASCII):\n");
                for (int i = 0; i < payload_len && i < 100; i++) {
                printf("%c", isprint(payload[i]) ? payload[i] : '.');
                }
                printf("\n");
            }
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}