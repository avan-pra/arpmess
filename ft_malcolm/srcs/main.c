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

#include "define.h"
#include "struct.h"
#include "argparse.h"
#include "utils.h"

int main(int argc, char **argv)
{
	SOCKET s = 0;
	unsigned char buf[4096] = { 0x0 }; // reduce
	eth eth_hdr;
	arp arp_hdr;
	attack attacks_infos;
	char ifacename[IFNAMSIZ];

	/* sample arp request packet for testing */
	unsigned char packet[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2, 0x42, 0xac, 0x11, 0x0, 0x3, 0x8, 0x6,\
	0x0, 0x1,\
	0x8, 0x0,\
	0x6,\
	0x4,\
	0x0, 0x1, 0x2, 0x42, 0xac, 0x11, 0x0, 0x3, 0xac, 0x11, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xac, 0x11, 0x0, 0x1 };

	// if (getuid() != 0)
	// 	{ BADUID(getuid()); return 1; }

	if (argc != 5)
		{ USAGE(); return 1; }

	/* set up attack structure (from argv)*/
	if (fill_ipv4_from_string(argv[1], attacks_infos.spoofed_pa) != 0)
		goto err;
	if (fill_mac_from_string(argv[2], attacks_infos.spoofed_ha) != 0)
		goto err;
	if (fill_ipv4_from_string(argv[3], attacks_infos.target_pa) != 0)
		goto err;
	if (fill_mac_from_string(argv[4], attacks_infos.target_ha) != 0)
		goto err;

	if (get_network_interface_name(ifacename) != 0)
		goto err;

	// printf("%d.%d.%d.%d\n", attacks_infos.spoofed_pa[0], attacks_infos.spoofed_pa[1], attacks_infos.spoofed_pa[2], attacks_infos.spoofed_pa[3]);

	// s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	// if (s == -1)
	// 	goto err;
	// if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4) == -1)
	// 	goto err;

	// recvfrom(s, buf, sizeof(buf), 0, NULL, 0);
	memcpy(buf, packet, sizeof(packet));
	eth_hdr = *(eth*)&buf;
	arp_hdr = *(arp*)&(buf[ETH_HDR_LEN]);

	close(s);
	return 0;

err:
	if (s > 0)
		close(s);
	if (errno != 0) {
		printf("Error: %s\n", strerror(errno));
		return 1;
	}
	return 1;
}
