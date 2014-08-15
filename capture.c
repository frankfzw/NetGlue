#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "type.h"
#include "capture.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;

    struct sniff_ethernet *ethernet;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;

    printf("Packet Number %d: \n", count);
    count ++;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20)
    {
        printf("Invalid IP header length: %u bytes", size_ip);
        return;
    }

    printf("%s --> %s", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            printf("\tProtocol TCP\n");
            break;
        case IPPROTO_UDP:
            printf("\tProtocol UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("\tProtocol ICMP\n");
            break;
        case IPPROTO_IP:
            printf("\tProtocol IP\n");
            break;
        default:
            printf("\tUnkown Protocol\n");
    }


}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: sudo %s DeviceName\n", argv[0]);
        return -1;
    }

	char *dev = argv[1], errbuf[PCAP_ERRBUF_SIZE];
    int num_pkts = 20;

    /*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find device: %s\n", errbuf);
        return 2;
    }
    */

    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
    {
         fprintf(stderr, "Can't get netmask for device %s\n", dev);
         net = 0;
         mask = 0;
    }

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet device\n", dev);
        return -1;
    }

    printf("Target Device: %s\n", dev);

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return -1;
    }

    //do not use filter so that it can grab all packet
    
    if (pcap_setfilter(handle, &fp) == -1) 
    {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return -1;
    }
    

    pcap_loop(handle, num_pkts, got_packet, NULL);

    return 0;
}