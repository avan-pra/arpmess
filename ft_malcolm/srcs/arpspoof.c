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

# include "define.h"
# include "struct.h"
# include "utils.h"

SOCKET initiate_socket_for_arp(char ifacename[IFNAMSIZ])
{
	SOCKET iface = 0;

	iface = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (iface == -1)
		goto err;
	if (setsockopt(iface, SOL_SOCKET, SO_BINDTODEVICE, ifacename, strlen(ifacename)) == -1)
		goto err;

	return iface;
err:
	if (iface > 0)
		close(iface);
	return(-1);	
}

int arpspoof(SOCKET iface, const attack *attacks_infos)
{
	unsigned char buf[4096] = { 0x0 };
	eth eth_hdr;
	arp arp_hdr;
	struct sockaddr addr;

	while (1)
	{
		recvfrom(iface, buf, sizeof(buf), 0, &addr, NULL);
		eth_hdr = *(eth*)&buf;
		arp_hdr = *(arp*)&(buf[ETH_HDR_LEN]);

		// sometrhing wrong arp_hdr.sender_pa */
		print_ipv4_address(arp_hdr.sender_pa);
		print_ipv4_address(attacks_infos->target_pa);
		
		if (is_mac_equal(eth_hdr.src_addr, attacks_infos->target_ha)
			&& is_ipv4_equal(arp_hdr.sender_pa, attacks_infos->target_pa))
		{
			printf("yay\n");
		}

		memset(buf, 0x0, 4096);
		// return 0;
	}
}