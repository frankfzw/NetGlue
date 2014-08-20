#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "type.h"
#include "capture.h"
#include "glue.h"



//host nic netmask and address
bpf_u_int32 _mask;
bpf_u_int32 _net;
bpf_u_int32 _2ndNet;
bpf_u_int32 _2ndMask;

u_char nic1MAC[ETHER_ADDR_LEN];
u_char nic2MAC[ETHER_ADDR_LEN];

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;

    struct sniff_ethernet *ethernet;
    struct sniff_ip *ip;
    //struct sniff_tcp *tcp;

    printf("Packet Number %d: \n", count);
    count ++;

    ethernet = (struct sniff_ethernet*)(packet);

    //test
    //printf("ethernet addr: %x:%x:%x:%x:%x:%x\n", 
        //ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20)
    {
        printf("Invalid IP header length: %u bytes", size_ip);
        return;
    }


    printf("%s --> %s", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
    //printf("\tsrc: %lu", (unsigned long)ip->ip_src.s_addr);

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

    //change the packet to SCION-like one
    //1. convert source address of ethernet frame
    changeMAC(ethernet, nic2MAC);

    //2. convert source IP address of ip packet
    changeIP(ip, (unsigned long)_2ndNet);
    


}



int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: sudo %s nic1 nic2\n", argv[0]);
        return -1;
    }

	char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev2 = argv[2];
    int num_pkts = 10;

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


    if (pcap_lookupnet(dev, &_net, &_mask, errbuf) == -1) 
    {
         fprintf(stderr, "Can't get netmask for nic1 %s\n", dev);
         _net = 0;
         _mask = 0;
    }

    if (pcap_lookupnet(dev2, &_2ndNet, &_2ndMask, errbuf) == -1) 
    {
         fprintf(stderr, "Can't get netmask for nic2 %s\n", dev2);
         _2ndNet = 0;
         _2ndMask = 0;
    }

    //get the MAC address of two nics
    getMAC(dev, nic1MAC);
    getMAC(dev2, nic2MAC);

    //print nic status
    struct in_addr net;
    _net = getNicIP(dev);
    net.s_addr = (unsigned long)_net;
    struct in_addr mask;
    mask.s_addr = (unsigned long)_mask;
    printf("Primary Device: %s\n", dev);
    printf("Address: %s\n", inet_ntoa(net));
    printf("Netmask: %s\n", inet_ntoa(mask));

    _2ndNet = getNicIP(dev2);
    net.s_addr = (unsigned long)_2ndNet;
    mask.s_addr = (unsigned long)_2ndMask;
    printf("Second Device: %s\n", dev2);
    printf("Address: %s\n", inet_ntoa(net));
    printf("Netmask: %s\n", inet_ntoa(mask));
    

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

    //set direction, only capture packets sent out of nic
    if (pcap_setdirection(handle, PCAP_D_OUT) == -1)
    {
        fprintf(stderr, "Set direction of filter failed\n");
        return -1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, _net) == -1)
    {
         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return -1;
    }

    
    if (pcap_setfilter(handle, &fp) == -1) 
    {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return -1;
    }
    

    pcap_loop(handle, num_pkts, got_packet, NULL);

    return 0;
}