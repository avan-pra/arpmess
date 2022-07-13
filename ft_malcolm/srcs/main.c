#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netdb.h>

# define SOCKET int
# define IPV4_LEN 4
# define ERROR_SAMPLE "Error: "
# define BAD_IP_ARGUMENT(IP) ( printf("%sunknown host or invalid IP address: (%s)\n", ERROR_SAMPLE, IP) )

#ifndef SO_BINDTODEVICE
# define SO_BINDTODEVICE 0x19	/* for vscode */
#endif

/* Ethernet frame header */
typedef struct {
	uint8_t dest_addr[6];	/* example: 02:42:ac:11:00:03 / hardware address */
	uint8_t src_addr[6];	/* same */
	uint16_t eth_type;	/* 0x0806 for ARP */
}	eth;

/* ARP packet */
typedef struct
{
	uint16_t htype; /* Hardware address space */
	uint16_t ptype; /* Protocol address space. */
	uint8_t hlen; /* byte len of each hardware addr */
	uint8_t plen; /* byte len of each protocol addr */
	uint8_t sender_ha[ETH_ALEN];	/* sender hardware addr */ 
	uint8_t sender_pa[IPV4_LEN];	/* sender protocol (IPv4) addr */
	uint8_t target_ha[ETH_ALEN];	/* target hardware addr */ 
	uint8_t target_pa[IPV4_LEN];	/* target protocol (IPv4) addr */
}	arp;

typedef struct
{
	uint8_t spoofed_pa[IPV4_LEN];	/* sender protocol (IPv4) addr */
	uint8_t spoofed_ha[ETH_ALEN];	/* sender hardware addr */ 
	uint8_t target_pa[IPV4_LEN];	/* target protocol (IPv4) addr */
	uint8_t target_ha[ETH_ALEN];	/* target hardware addr */ 
}	attack;


# define ETH_HDR_LEN sizeof(eth)

/* return wheter the given addr is a hardware broadcast address */
int is_hbroadcast_addr(uint8_t addr[6])
{
	for (size_t i = 0; i < 6; ++i) {
		if (addr[i] != 255)
			return 0;	
	}
	return 1;
}

int fill_ipv4_from_string(char *str, uint8_t buf[IPV4_LEN])
{
	struct addrinfo *infos = 0x0;
	char *ptr = str;
	char ipstr[INET_ADDRSTRLEN];
	int status = 0;

	/* this part check if its a hostname and resolve it if so*/
	if (inet_addr(str) == -1) {
		struct addrinfo hint;
		struct addrinfo *save_infos;

		memset(&hint, 0, sizeof(hint));
		hint.ai_family = AF_UNSPEC;
		hint.ai_socktype = SOCK_STREAM;
		getaddrinfo(str, "", &hint, &infos);

		/* keep a pointer to getaddrinfo return to be able to free it later on */
		save_infos = infos;

		/* loop through getaddrinfo return, stopping at an ipv4 address */
		while (infos != NULL && infos->ai_family != AF_INET)
			infos = infos->ai_next;

		/* we did not found an ipv4 address OR the supplied hostname is shit */
		if (infos == NULL)
		{ BAD_IP_ARGUMENT(str); infos = save_infos; status = 1; goto ret; }

		/* put a readble ipv4 addr in ipstr */
		inet_ntop(infos->ai_family, &((struct sockaddr_in *)infos->ai_addr)->sin_addr, ipstr, sizeof(ipstr));
		infos = save_infos;
		ptr = ipstr;
	}

	/* fill buf with the ipv4 address supplied OR the one found by getaddrinfo */
	sscanf(ptr, "%hhd.%hhd.%hhd.%hhd",\
	&buf[0], &buf[1],\
	&buf[2], &buf[3]);

ret:
	if (infos != NULL)
		freeaddrinfo(infos);
	return status;
}

int main(int argc, char **argv)
{
	SOCKET s;
	unsigned char buf[4096] = { 0x0 };

	/* sample arp request packet for testing */
	unsigned char packet[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2, 0x42, 0xac, 0x11, 0x0, 0x3, 0x8, 0x6,\
	0x0, 0x1,\
	0x8, 0x0,\
	0x6,\
	0x4,\
	0x0, 0x1, 0x2, 0x42, 0xac, 0x11, 0x0, 0x3, 0xac, 0x11, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xac, 0x11, 0x0, 0x1 };
	eth eth_hdr;
	arp arp_hdr;
	attack attacks_infos;

	if (argc != 5)
		goto usage;

	/* set up attack structure */
	if (fill_ipv4_from_string(argv[1], attacks_infos.spoofed_pa) != 0)
		goto err;
	// spoofed HA
	if (fill_ipv4_from_string(argv[3], attacks_infos.target_pa) != 0)
		goto err;
	// target HA

	printf("%d.%d.%d.%d", attacks_infos.spoofed_pa[0], attacks_infos.spoofed_pa[1], attacks_infos.spoofed_pa[2], attacks_infos.spoofed_pa[3]);

	// s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	// if (s == -1)
	// 	goto err;
	// if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4) == -1)
	// 	goto err;

	// recvfrom(s, buf, sizeof(buf), 0, NULL, 0);
	memcpy(buf, packet, sizeof(packet));
	eth_hdr = *(eth*)&buf;
	arp_hdr = *(arp*)&(buf[ETH_HDR_LEN]);

err:
	if (s > 0)
		close(s);
	if (errno != 0) {
		printf("Error: %s\n", strerror(errno));
		return 1;
	}
	return 0;

usage: ;
	char usage_str[] = "Usage: <spoofed_ip> <spoofed_mac> <origin_ip> <origin_mac>";
	printf("%s\n", usage_str);
}
