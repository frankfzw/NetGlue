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

char *nicName;
char *nicName2;


void filterOut(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */
    
    /* declare pointers to packet headers */
    struct ether_header *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */

    int size_ip;
    //int size_tcp;
    
    printf("\nPacket number %d:\n", count);
    log("\nPacket number %d:\n", count);
    count++;
    printf("Original Info\n");
    //char *temp = (char *)packet;
    //printf("Size of Frame: %d\n", strlen(temp));
    /* define ethernet header */
    ethernet = (struct ether_header*)(packet);
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
    switch(ip->ip_p) 
    {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            printTCP((struct sniff_tcp *)((u_char *)ip + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            printUDP((struct udphdr *)((u_char *)ip + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            printICMP((struct icmp6_hdr *)((u_char *)ip + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n");
            break;
        default:
            printf("Protocol: unknown\n");
            return;
    }



    
    //change the packet to SCION-like one
    //1. convert source address of ethernet frame
    changeMAC(ethernet, nic2MAC, false);

    //2. convert source IP address of ip packet and recalculate ip checksum
    changeIP(ip, (unsigned long)_2ndNet, false);

    //3. convert to SCION-packet and send
    u_char newPkt[MAX_ETH_MTU];
    int len = convertToSCION((u_char *)ethernet, newPkt);

    //printIP(ip);

    if (len < 0)
        log("Out: Converting error\n");

    //4. send packet
    int res = sendPacket(newPkt, len, nicName2, ethernet->ether_dhost, ip->ip_dst.s_addr, DATA_PROTO);

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
    //struct ether_header *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */

    int size_ip;
    //int size_tcp;
    
    printf("\nPacket number %d:\n", count);
    log("\nPacket number %d:\n", count);
    count++;
    printf("Original Info\n");
    
    /* define ethernet header */
    //ethernet = (struct ether_header*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }


    switch(ip->ip_p) 
    {
        case DATA_PROTO:
            printf("Protocol DATA\n");
            break;
        case CONTROL_PROTO:
            printf("Protocol CONTROL\n");
            break;
        default:
            printf("Protocol Unknown\n");
            return;
    }

    //get the original packet from payload of SCION
    //1. split the ethnet head and ip head, get the original ethernet frame
    u_char buf[MAX_ETH_MTU];
    struct ether_header *eth = (struct ether_header *)buf;
    int size = fromSCION((u_char *)ip, eth);
    if (size < 0)
    {
        log("Convert from SCION error\n");
        return;
    }

    //Print info of eth frame
    printETH(eth);
    struct sniff_ip *iph = (struct sniff_ip*)(buf + SIZE_ETHERNET);

    /* print source and destination IP addresses */
    printIP(iph);

    /* determine protocol */    
    switch(iph->ip_p) 
    {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            printTCP((struct sniff_tcp *)((u_char *)iph + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            printUDP((struct udphdr *)((u_char *)iph + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            printICMP((struct icmp6_hdr *)((u_char *)iph + sizeof(struct sniff_ip)));
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n");
            break;
        default:
            printf("Protocol: unknown\n");
            break;
    }

    //1. convert source address of ethernet frame
    changeMAC(eth, nic1MAC, true);

    //2. convert source IP address of ip packet and recalculate ip checksum
    struct sniff_ip *originalIPH = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    changeIP(originalIPH, (unsigned long)_net, true);

    //3. send raw socket to nic1
    int res = sendRaw(buf, size, nicName, nic1MAC);
    if (res < 0)
        log("In: Send to NIC:%s failed. No. %d", nicName, count);


}



int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: sudo %s nic1 nic2 direction(in or out)\n", argv[0]);
        return -1;
    }

	nicName = argv[1];
    nicName2 = argv[2];
    char *direction = argv[3];
    int num_pkts = -1;
    pcap_t *handle;


    //clear log at first
    clearLog();

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(nicName, &_net, &_mask, errbuf) == -1) 
    {
         fprintf(stderr, "Can't get netmask for nic1 %s\n", nicName);
         _net = 0;
         _mask = 0;
    }

    if (pcap_lookupnet(nicName2, &_2ndNet, &_2ndMask, errbuf) == -1) 
    {
         fprintf(stderr, "Can't get netmask for nic2 %s\n", nicName2);
         _2ndNet = 0;
         _2ndMask = 0;
    }

    //get the MAC address of two nics
    getMAC(nicName, nic1MAC);
    getMAC(nicName2, nic2MAC);

    //print nic status
    struct in_addr net;
    _net = getNicIP(nicName);
    net.s_addr = (unsigned long)_net;
    struct in_addr mask;
    mask.s_addr = (unsigned long)_mask;
    log("Primary NIC: %s\n", nicName);
    log("Address: %s\n", inet_ntoa(net));
    log("Netmask: %s\n", inet_ntoa(mask));

    _2ndNet = getNicIP(nicName2);
    net.s_addr = (unsigned long)_2ndNet;
    mask.s_addr = (unsigned long)_2ndMask;
    log("Second NIC: %s\n", nicName2);
    log("Address: %s\n", inet_ntoa(net));
    log("Netmask: %s\n", inet_ntoa(mask));

    if (strcmp(direction, "out") == 0)
    {
        handle = pcap_open_live(nicName, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open NIC %s: %s\n", nicName, errbuf);;
            return -1;
        }
        setDevice(PCAP_D_OUT, _net, "ip", nicName, handle);
        pcap_loop(handle, num_pkts, filterOut, NULL);
    }
    else if (strcmp(direction, "in") == 0)
    {
        handle = pcap_open_live(nicName2, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open nicNameice %s: %s\n", nicName, errbuf);;
            return -1;
        }
        setDevice(PCAP_D_IN, _2ndNet, "ip", nicName2, handle);
        pcap_loop(handle, num_pkts, filterIn, NULL);
    }
    /*
    handle2 = pcap_open_live(nicName2, SNAP_LEN, 1, 1000, errbuf);
    if (handle2 == NULL)
    {
        fprintf(stderr, "Couldn't open NIC %s: %s\n", nicName2, errbuf);
        return -1;
    }
    setDevice(_2ndNet, "ip", nicName2, handle2);
    pcap_loop(handle, num_pkts, filter2, NULL);
    */

    printf("Capture is running!\n");
    return 0;
}