#include "glue.h"
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "type.h"

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

	u_short origin = packet->ip_sum;
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
