#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "capture.h"
#include "glue.h"



//host nic netmask and address
bpf_u_int32 _mask;
bpf_u_int32 _net;
bpf_u_int32 _2ndNet;
bpf_u_int32 _2ndMask;

u_char nic1MAC[ETHER_ADDR_LEN];
u_char nic2MAC[ETHER_ADDR_LEN];


void filterOut(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */
    
    /* declare pointers to packet headers */
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */

    int size_ip;
    //int size_tcp;
    
    printf("\nPacket number %d:\n", count);
    count++;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    printETH(ethernet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("* Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printIP(ip);

    /* determine protocol */    
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            printTCP((struct sniff_tcp *)(ip + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            printUDP((struct udphdr *)(ip + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            printICMP((struct icmp6_hdr *)(ip + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n");
            break;
        default:
            printf("Protocol: unknown\n");
            break;
    }



    
    //change the packet to SCION-like one
    //1. convert source address of ethernet frame
    changeMAC(ethernet, nic2MAC);

    //2. convert source IP address of ip packet and recalculate ip checksum
    changeIP(ip, (unsigned long)_2ndNet);

    //3. convert to SCION-packet and send
    u_char newPkt[MAX_ETH_MTU];
    convertToSCION(ethernet, newPkt);

    //4. send packet
    int res = sendPacket(packet, "wlan0", ethernet->ether_dhost, ip->ip_dst.s_addr);

    if (res == 0)
    {
        log("Send successfully: No.%d\n", count);
    }
    else
        log ("Send failed: No.%d\n", count);

    


}

void filterIn(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */
    
    /* declare pointers to packet headers */
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */

    int size_ip;
    //int size_tcp;
    
    printf("\nPacket number %d:\n", count);
    count++;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }


    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));


    /* determine protocol */    
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            //printf("\nPacket number %d:\n", count);
            printf("   Protocol: ICMP\n");
            break;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }


}



int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: sudo %s nic1 nic2 direction(in or out)\n", argv[0]);
        return -1;
    }

	char *dev = argv[1];
    char *dev2 = argv[2];
    char *direction = argv[3];
    int num_pkts = -1;
    pcap_t *handle;


    //clear log at first
    clearLog();

    char errbuf[PCAP_ERRBUF_SIZE];
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
    log("Primary Device: %s\n", dev);
    log("Address: %s\n", inet_ntoa(net));
    log("Netmask: %s\n", inet_ntoa(mask));

    _2ndNet = getNicIP(dev2);
    net.s_addr = (unsigned long)_2ndNet;
    mask.s_addr = (unsigned long)_2ndMask;
    log("Second Device: %s\n", dev2);
    log("Address: %s\n", inet_ntoa(net));
    log("Netmask: %s\n", inet_ntoa(mask));

    if (strcmp(direction, "out") == 0)
    {
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);;
            return -1;
        }
        setDevice(PCAP_D_OUT, _net, "ip", dev, handle);
        pcap_loop(handle, num_pkts, filterOut, NULL);
    }
    else if (strcmp(direction, "in") == 0)
    {
        handle = pcap_open_live(dev2, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);;
            return -1;
        }
        setDevice(PCAP_D_IN, _2ndNet, "ip", dev2, handle);
        pcap_loop(handle, num_pkts, filterIn, NULL);
    }
    /*
    handle2 = pcap_open_live(dev2, SNAP_LEN, 1, 1000, errbuf);
    if (handle2 == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev2, errbuf);
        return -1;
    }
    setDevice(_2ndNet, "ip", dev2, handle2);
    pcap_loop(handle, num_pkts, filter2, NULL);
    */

    printf("Capture is running!\n");
    return 0;
}