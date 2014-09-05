#include "glue.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include "./lib/packetheader.hh"
#include "./lib/raw_sock.h"
#include "./lib/scionpathinfo.hh"


#include <pcap.h>
//#include "sockEth.h"



//add some arguements to test
#define MAX_PATH_LEN 1024
#define FIRST_ER "192.168.6.63"
#define KEY "Secret key shared between Client6 and Client7"



// Emulation and should be replaced by get_path query to cliendaemon.
// Return len of the path from AD6 to AD7 in TD1, and copy path to buf, which
// must be allocated 
int get_path(int TD, int AD,uint8_t *buf){
    // memcpy(buf, "\x80\x70\x73\x8f\x52\x01\x00\x03\x00\x3f\x00\x00\x00\x37\x9e\x2e\x00\x1f\x00\x24\x00\xc2\xa0\x27\x20\x00\x00\x0d\x00\x31\x25\x82\x80\xce\x76\x8f\x52\x01\x00\x03\x20\x00\x00\x0e\x00\x31\x25\x82\x00\x29\x00\x2f\x00\xf4\x07\x66\x00\x4a\x00\x00\x00\x37\x9e\x2e", 64);
    // return 64;
memcpy(buf,"\x80\x13\x78\x01\x00\x03\x00\x00\x00\x3f\x00\x00\x00\x9f\x30\x5a\x00\x1f\x00\x24\x00\x3f\x89\xe9\x20\x00\x00\x0d\x00\xcf\xd1\x4d\x80\x19\x78\x01\x00\x03\x00\x00\x20\x00\x00\x0e\x00\x1a\xee\xdd\x00\x29\x00\x2f\x00\x41\x92\xd9\x00\x4a\x00\x00\x00\x3b\x75\xd2",64);
    return 64;
}
//basing on opaque field should return first ER
char * get_first_hop(uint8_t *path){
    return (char*)FIRST_ER; 
}


void changeMAC(struct sniff_ethernet *packet, u_char *nicMAC)
{
	//chage ethernet source addr
	log("Change MAC of packet: %x:%x:%x:%x:%x:%x --> ", 
		packet->ether_shost[0], packet->ether_shost[1], packet->ether_shost[2], packet->ether_shost[3], packet->ether_shost[4], packet->ether_shost[5]);
	memset(packet->ether_shost, 0, ETHER_ADDR_LEN);
	memcpy(packet->ether_shost, nicMAC, ETHER_ADDR_LEN);
	log("%x:%x:%x:%x:%x:%x\n", 
		packet->ether_shost[0], packet->ether_shost[1], packet->ether_shost[2], packet->ether_shost[3], packet->ether_shost[4], packet->ether_shost[5]);
}

void changeIP(struct sniff_ip *packet, unsigned long src)
{
	log("Change IP of packet: %s --> ", inet_ntoa(packet->ip_src));
	packet->ip_src.s_addr = src;
	log("%s\n", inet_ntoa(packet->ip_src));

	//recalculate ip checksum
	checksum(packet);
}



unsigned long getNicIP(char *dev)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}


void getMAC(char *dev, u_char *MAC)
{
    FILE *file;
    char nicDir[NIC_DIR_LEN];
    strcpy(nicDir, "/sys/class/net/");
    strcat(nicDir, dev);
    strcat(nicDir, "/address");
    file = fopen(nicDir, "r");
    char *buf = (char *)malloc(17 * sizeof(char));
    char *temp = buf;
    fscanf(file, "%s", buf);
    fclose(file);
    //log("MAC address of %s: %c%c%c%c\nsizof: %d\n", dev, temp[0], temp[1], temp[2], temp[3], (int)strlen(temp));

    //convert to hex
    memset(MAC, 0, ETHER_ADDR_LEN);

    int i = 0;
    int len = (int)strlen(temp);
    for (; i < len; i += 3)
    {
        temp[i+2] = '\0';
        int mac_byte;
        sscanf(buf, "%x", &mac_byte);
        unsigned char mac = mac_byte & 0xff;
        //log("\ttest: %x\n", mac);
        MAC[i/3] = mac;
        //log("MAC addr test: %d: %x\n", i/3, MAC[i/3]);
        buf += 3 * sizeof(char);
    }

    log("MAC address of %s: %x:%x:%x:%x:%x:%x\n", dev, 
        MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

    free(temp);


}

void checksum(struct sniff_ip *packet)
{
	u_char *temp = (u_char *)packet;
	u_int ip_sum = 0;

	//u_short origin = packet->ip_sum;
	packet->ip_sum = 0;


	//log("%s --> %s\n", inet_ntoa(packet->ip_src), inet_ntoa(packet->ip_dst));
	//log("%x --> %x\n", packet->ip_src.s_addr, packet->ip_dst.s_addr);

	//calculate size per 16 bits
	int size_ip = IP_HL(packet) * 2;
    
	int i = 0;
    for (; i < size_ip; i ++)
    {
    	u_short cal = ((*temp) << 8) + *(temp + 1);
    	//log("step %d: val\t%x add %x\n", i, ip_sum, cal);
    	u_int step = ip_sum + cal;
    	ip_sum = (step + ((step >> 16) & 0x1)) & 0xffff;
    	temp += 2;

    }
    ip_sum = ~ip_sum & 0xffff;

    //change the format to big endding
    u_short result = ((ip_sum & 0xff) << 8) + ((ip_sum & 0xff00) >> 8);
    packet->ip_sum = result;
    //log("checksum: %x --> %x\n", origin, packet->ip_sum);
}

void convertToSCION(struct sniff_ethernet *packet, u_char *newPkt)
{
    struct sniff_ip *ip;
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    uint8_t path[MAX_PATH_LEN];
    struct in_addr tmp;
    int path_len=get_path(1,7,path);
    int totalLen; 
    if (!path_len)
    {
        log("Get path error!\n");
        return;
    }

    const char *payload = (char *)packet;
    
    //4s are for IPv4 , 16 is for ext
    totalLen=COMMON_HEADER_SIZE + 4 + 4 + path_len + 16 + strlen(payload); 
    int hdrLen=COMMON_HEADER_SIZE + 4 + 4 + path_len;
    uint8_t pkt[totalLen];

    //header
    //TODO one function for that
    SPH::setUppathFlag(pkt);
    if (!inet_pton(AF_INET, inet_ntoa(ip->ip_src), &tmp))
    {
        log("Set source address error\n");
        return;
    }
    SPH::setSrcAddr(pkt, HostAddr(HOST_ADDR_IPV4, tmp.s_addr));
    if (!inet_pton(AF_INET, inet_ntoa(ip->ip_dst), &tmp))
    {
        log("Set destination address error\n");
        return;
    }
    SPH::setDstAddr(pkt, HostAddr(HOST_ADDR_IPV4,tmp.s_addr));
    SPH::setTotalLen(pkt, totalLen);
    SPH::setTimestampPtr(pkt, 4+4);
    SPH::setCurrOFPtr(pkt, 4+4);
    SPH::setNextHdr(pkt, 200);
    SPH::setHdrLen(pkt, hdrLen);

    //path
    memcpy(pkt+COMMON_HEADER_SIZE+4+4, path,path_len);
    
    //extension header
    scionExtensionHeader *extHdr = (scionExtensionHeader*)(pkt + hdrLen);
    //that terminates (there is no next ext) - something else should terminate,
    //because 0 is reserved for IPv6 hop-by-hop
    extHdr->nextHdr = 0;
    extHdr->hdrLen = 16;//14 other bytes are for extension 

    //data after extension header
    memcpy(pkt + hdrLen + extHdr->hdrLen, payload, strlen(payload));

    //extension handling: extension computes HMAC over whole packet without
    //common header, and put tag into 14 bytes of SCION extension (type: 200)
    memset(pkt + hdrLen + 2,'\x00',14);//HMAC encompasses that - must be constant
    unsigned char* digest;
    digest = HMAC(EVP_sha1(), KEY, strlen(KEY), (unsigned char*)pkt+8, totalLen-8, NULL, NULL);  
    //truncated MAC insertion
    memcpy(pkt + hdrLen + 2, digest, 14);
    log("MAC: ");
    for (int i=0; i < 14; i ++)
        log("%02x", digest[i]);
    log("\nSending...");

    //send_raw(inet_ntoa(ip->ip_src), get_first_hop(path), pkt, totalLen, DATA_PROTO);
    memcpy(newPkt, pkt, totalLen);
}

int sendPacket(const u_char *packet, char *dev, u_char *dstMAC, unsigned long daddr)
{
    /*
    int fd;
    struct ifreq ifr;
    struct sockaddr_ll socket_address = {0};

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd == -1)
    {
        printf("sendPacket: socket error\n");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    int ifindex = ifr.ifr_ifindex;

    socket_address.sll_ifindex = ifindex;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_halen = ETHER_ADDR_LEN;
    socket_address.sll_protocol = htons(ETH_P_IP);
    memcpy(socket_address.sll_addr, packet->ether_dhost, ETHER_ADDR_LEN);
    if (sendto(fd, packet, sizeof(*packet), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0)
    {
        printf("Send failed\n");
        return -1;
    }

 
    return 0;
    */
    int tx_len = 0;
    u_char sendbuf[MAX_ETH_MTU];
    struct ether_header *eh = (struct ether_header *) sendbuf;
    u_char srcMAC[ETHER_ADDR_LEN];

    getMAC(dev, srcMAC);

    /* Construct the Ethernet header */
    memset(sendbuf, 0, MAX_ETH_MTU);
    /* Ethernet header */
    memcpy(eh->ether_shost, srcMAC, ETHER_ADDR_LEN);
    // eh->ether_shost[0] = srcMAC[0];
    // eh->ether_shost[1] = srcMAC[1];
    // eh->ether_shost[2] = srcMAC[2];
    // eh->ether_shost[3] = srcMAC[3];
    // eh->ether_shost[4] = srcMAC[4];
    // eh->ether_shost[5] = srcMAC[5];
    memcpy(eh->ether_dhost, dstMAC, ETHER_ADDR_LEN);
    // eh->ether_dhost[0] = dstMAC[0];
    // eh->ether_dhost[1] = dstMAC[1];
    // eh->ether_dhost[2] = dstMAC[2];
    // eh->ether_dhost[3] = dstMAC[3];
    // eh->ether_dhost[4] = dstMAC[4];
    // eh->ether_dhost[5] = dstMAC[5];
    /* Ethertype field */
    eh->ether_type = htons(ETH_P_IP);
    tx_len += sizeof(struct ether_header);

    struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    /* IP Header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->ttl = 64;
    iph->frag_off = 0;       /* no fragment */
    iph->protocol = DATA_PROTO;
    //iph->protocol = IPPROTO_ICMP; //for test
    iph->check = 0; 
    /* Source IP address, can be spoofed */
    iph->saddr = getNicIP(dev);
    // iph->saddr = inet_addr("192.168.0.112");
    /* Destination IP address */
    iph->daddr = daddr;

    int len = sizeof(packet) / sizeof(u_char);
    iph->tot_len = htons(sizeof(struct iphdr) + len);
    tx_len += sizeof(struct iphdr);

    memcpy((sendbuf + tx_len), packet, len);

    tx_len += len;
    checksum((struct sniff_ip *)iph);
    
    /*
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);;
        return -1;
    }

    if (pcap_inject(handle, (void *)sendbuf, tx_len == -1))
    {
        printf("Send packet error\n");
        return -1;
    }
    pcap_close(handle);
    */

    int sockfd;
    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("socket");
    }

    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    struct sockaddr_ll socket_address;
    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    // socket_address.sll_addr[0] = dstMAC[0];
    // socket_address.sll_addr[1] = dstMAC[0];
    // socket_address.sll_addr[2] = dstMAC[0];
    // socket_address.sll_addr[3] = dstMAC[0];
    // socket_address.sll_addr[4] = dstMAC[0];
    // socket_address.sll_addr[5] = dstMAC[0];
    memcpy(socket_address.sll_addr, dstMAC, ETHER_ADDR_LEN);
 
    /* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    {
        printf("Send failed\n");
        return -1;
    }
    return 0;
    
}

void setDevice(pcap_direction_t direction, bpf_u_int32 net, char *filter_exp, char *dev, pcap_t *handle)
{
    struct bpf_program fp;

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet device\n", dev);
        return;
    }

    //set direction, only capture packets sent out of nic
    if (pcap_setdirection(handle, PCAP_D_OUT) == -1)
    {
        fprintf(stderr, "Set direction of filter failed\n");
        return;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return;
    }

    
    if (pcap_setfilter(handle, &fp) == -1) 
    {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return;
    }

    printf("Device %s is ready\n", dev);
}

void log(const char *fmt, ...)
{
    FILE *file;
    file = fopen("log.txt", "a+");

    va_list args;
    va_start(args, fmt);
    vfprintf(file, fmt, args);
    va_end(args);

    fclose(file);
}

void clearLog()
{
    FILE *file;
    file = fopen("log.txt", "w");
    fclose(file);
}

void printMAC(u_char *mac)
{
    printf("MAC: %x:%x:%x:%x:%x:%x", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void printTCP(struct sniff_tcp *packet)
{
    printf("TCP Header:\n");
    printf("\tSource port: 0x%x\n", packet->th_sport);
    printf("\tDestination prot: 0x%x\n", packet->th_dport);
    printf("\tSeq Number: 0x%x\n", packet->th_seq);
    printf("\tAck Number: 0x%x\n", packet->th_ack);
    printf("\tData offset: 0x%x\n", TH_OFF(packet));
    printf("\tWindow size: 0x%x\n", packet->th_win);
    printf("\tChecksum: 0x%x\n", packet->th_sum);
}

void printUDP(struct udphdr* udph)
{
    printf("UDP Header:\n");
    printf("\tSource port: 0x%x\n", udph->source);
    printf("\tDestination port: 0x%x\n", udph->dest);
    printf("\tLength: 0x%x\n", udph->len);
    printf("\tChecksum: 0x%x\n", udph->check);
}

void printICMP(struct icmp6_hdr *icmph)
{
    printf("ICMP Header:\n");
    printf("\tType: 0x%x\n", icmph->icmp6_type);
    printf("\tCode: 0x%x\n", icmph->icmp6_code);
    printf("\tChecksum: 0x%x\n", icmph->icmp6_cksum);
}

void printETH(struct sniff_ethernet *eth)
{
    printf("Ethernet Header:\n");
    printf("\tFrom: ");
    printMAC(eth->ether_shost);
    printf("\n\tTo: ");
    printMAC(eth->ether_dhost);
    printf("\n");
}

void printIP(struct sniff_ip *iph)
{
    printf("IP Header:\n");
    printf("\tHeader Length: 0x%x\n", IP_HL(iph));
    printf("\tVersion: 0x%x\n", IP_V(iph));
    printf("\tService: 0x%x\n", iph->ip_tos);
    printf("\tTotal Length: 0x%x", iph->ip_len);
    printf("\tID: 0x%x\n", iph->ip_id);
    printf("\tChecksum: 0x%x\n", iph->ip_sum);
    printf("\tFrom: %s\n", inet_ntoa(iph->ip_src));
    printf("\tTo: %s\n", inet_ntoa(iph->ip_dst));
}
