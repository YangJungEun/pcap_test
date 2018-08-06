#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <netinet/ip.h>
#pragma pack (push,1)

struct ether
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct ip_header
{
    uint8_t  h_length:4;
    uint8_t  version:4;
    uint8_t  tos;
    uint16_t t_length;
    uint16_t Identifier;
    uint16_t flags:3;
    uint16_t fragment_offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t ip_option[3];
    uint8_t padding;
};



struct tcp_header{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved:4;
    uint8_t  offset:4;
    uint8_t tcp_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint32_t tcp_option;
};

#pragma pack (pop)

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void print_ipv4(uint32_t ip){

    printf("%u.%u.%u.%u\n",(ip&0xff000000)>>24,(ip&0x00ff0000)>>16,(ip&0x0000ff00)>>8,(ip&0x000000ff));

}

int main(int argc, char* argv[]) {

    if (argc != 2)
    {
        usage();
        return -1;
    }

    struct in_addr addr;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("< %u bytes captured >\n", header->caplen);

        struct ether *eth=(struct ether *)packet;
        printf("DESTINATION_MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->dst_mac[0],eth->dst_mac[1],eth->dst_mac[2],eth->dst_mac[3],eth->dst_mac[4],eth->dst_mac[5]);
        printf("SOURCE_MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n",eth->src_mac[0],eth->src_mac[1],eth->src_mac[2],eth->src_mac[3],eth->src_mac[4],eth->src_mac[5]);

        if(ntohs(eth->type)==ETHERTYPE_IP)
        {

            packet+=sizeof(ether);

            struct ip_header *iphdr=(struct ip_header *)packet;

            printf("Source_ip: " );
            print_ipv4(ntohl(iphdr->src_ip));
            printf("Dest_ip: " );
            print_ipv4(ntohl(iphdr->dst_ip));
            printf("\n");

            if(iphdr->protocol==IPPROTO_TCP)
            {

                packet+=(iphdr->h_length)*4;
                struct tcp_header *tcphdr=(struct tcp_header *)packet;

                printf("SOURCE_PORT: %d\n", ntohs(tcphdr->src_port));
                printf("DESTINATION_PORT: %d\n", ntohs(tcphdr->dst_port));


                packet+=tcphdr->offset*4;

                unsigned int a = ntohs(iphdr->t_length)-iphdr->h_length*4-tcphdr->offset*4;
                //printf("%d\n",a);

                if( a >= 16 )
                {
                    for(int i=0; i<16; i++) //header->length
                    {
                        if(i%16==0)
                             printf("\n");
                         printf("%02x ",packet[i]);
                    }
                }
                else                {
                    for(int i=0; i<a; i++) //header->length
                    {
                         printf("%02x ",packet[i]);
                    }
                    printf("\n");
                }

                printf("\n");
            } // port , data
            else
            {
                printf("<unknown>");
            }


        } // ip

        else
        {
            printf("unknown type\n");
        }

        printf("-----------------------------\n");

    }

    pcap_close(handle);
    return 0;
}
