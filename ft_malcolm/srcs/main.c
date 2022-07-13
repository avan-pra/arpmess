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

# define SOCKET int

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
	uint32_t sender_pa;	/* sender protocol (IPv4) addr */
	uint8_t target_ha[ETH_ALEN];	/* target hardware addr */ 
	uint32_t target_pa;	/* target protocol (IPv4) addr */
}	arp;

# define ETH_HDR_LEN sizeof(eth)

int main(void)
{
	SOCKET s;
	unsigned char buf[4096] = { 0x0 };
	unsigned char packet[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2, 0x42, 0xac, 0x11, 0x0, 0x3, 0x8, 0x6,\
	0x0, 0x1,\
	0x8, 0x0,\
	0x6,\
	0x4,\
	0x0, 0x1, 0x2, 0x42, 0xac, 0x11, 0x0, 0x3, 0xac, 0x11, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xac, 0x11, 0x0, 0x1 };
	eth eth_hdr;
	arp arp_hdr;

	// s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	// if (s == -1)
	// 	goto err;
	// if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4) == -1)
	// 	goto err;

	// recvfrom(s, buf, sizeof(buf), 0, NULL, 0);
	memcpy(buf, packet, sizeof(packet));
	eth_hdr = *(eth*)&buf;
	arp_hdr = *(arp*)&(buf[ETH_HDR_LEN]);
	printf("%d\n", arp_hdr.hlen);

err:
	if (s > 0)
		close(s);
	if (errno != 0)
		printf("%s\n", strerror(errno));
}
