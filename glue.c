#include "glue.h"
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <openssl/hmac.h>
#include "./lib/packetheader.hh"
#include "./lib/raw_sock.h"
#include "./lib/scionpathinfo.hh"

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
	printf("Change MAC of packet: %x:%x:%x:%x:%x:%x --> ", 
		packet->ether_shost[0], packet->ether_shost[1], packet->ether_shost[2], packet->ether_shost[3], packet->ether_shost[4], packet->ether_shost[5]);
	memset(packet->ether_shost, 0, ETHER_ADDR_LEN);
	memcpy(packet->ether_shost, nicMAC, ETHER_ADDR_LEN);
	printf("%x:%x:%x:%x:%x:%x\n", 
		packet->ether_shost[0], packet->ether_shost[1], packet->ether_shost[2], packet->ether_shost[3], packet->ether_shost[4], packet->ether_shost[5]);
}

void changeIP(struct sniff_ip *packet, unsigned long src)
{
	printf("Change IP of packet: %s --> ", inet_ntoa(packet->ip_src));
	packet->ip_src.s_addr = src;
	printf("%s\n", inet_ntoa(packet->ip_src));

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
    //printf("MAC address of %s: %c%c%c%c\nsizof: %d\n", dev, temp[0], temp[1], temp[2], temp[3], (int)strlen(temp));

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
        //printf("\ttest: %x\n", mac);
        MAC[i/3] = mac;
        //printf("MAC addr test: %d: %x\n", i/3, MAC[i/3]);
        buf += 3 * sizeof(char);
    }

    printf("MAC address of %s: %x:%x:%x:%x:%x:%x\n", dev, 
        MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

    free(temp);


}

void checksum(struct sniff_ip *packet)
{
	u_char *temp = (u_char *)packet;
	u_int ip_sum = 0;

	//u_short origin = packet->ip_sum;
	packet->ip_sum = 0;


	//printf("%s --> %s\n", inet_ntoa(packet->ip_src), inet_ntoa(packet->ip_dst));
	//printf("%x --> %x\n", packet->ip_src.s_addr, packet->ip_dst.s_addr);

	//calculate size per 16 bits
	int size_ip = IP_HL(packet) * 2;
    
	int i = 0;
    for (; i < size_ip; i ++)
    {
    	u_short cal = ((*temp) << 8) + *(temp + 1);
    	//printf("step %d: val\t%x add %x\n", i, ip_sum, cal);
    	u_int step = ip_sum + cal;
    	ip_sum = (step + ((step >> 16) & 0x1)) & 0xffff;
    	temp += 2;

    }
    ip_sum = ~ip_sum & 0xffff;

    //change the format to big endding
    u_short result = ((ip_sum & 0xff) << 8) + ((ip_sum & 0xff00) >> 8);
    packet->ip_sum = result;
    //printf("checksum: %x --> %x\n", origin, packet->ip_sum);
}

void convertToSCION(struct sniff_ethernet *packet)
{
    struct sniff_ip *ip;
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    uint8_t path[MAX_PATH_LEN];
    struct in_addr tmp;
    int path_len=get_path(1,7,path);
    int totalLen; 
    if (!path_len)
    {
        printf("Get path error!\n");
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
        printf("Set source address error\n");
        return;
    }
    SPH::setSrcAddr(pkt, HostAddr(HOST_ADDR_IPV4, tmp.s_addr));
    if (!inet_pton(AF_INET, inet_ntoa(ip->ip_dst), &tmp))
    {
        printf("Set destination address error\n");
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
    printf("MAC: ");
    for (int i=0; i < 14; i ++)
        printf("%02x", digest[i]);
    printf("\nSending...");

    send_raw(inet_ntoa(ip->ip_src), get_first_hop(path), pkt, totalLen, DATA_PROTO);
}