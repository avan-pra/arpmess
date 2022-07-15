#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

# include "define.h"

void print_mac_address(const uint8_t addr[ETH_ALEN])
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void print_ipv4_address(const uint8_t addr[IPV4_LEN])
{
	printf("%d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
}

void copy_ipv4(uint8_t dest[IPV4_LEN], const uint8_t src[IPV4_LEN])
{
	for (size_t i = 0; i < IPV4_LEN; ++i)
		dest[i] = src[i];
}

void copy_mac(uint8_t dest[ETH_ALEN], const uint8_t src[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i)
		dest[i] = src[i];
}

int is_ipv4_equal(const uint8_t pa1[IPV4_LEN], const uint8_t pa2[IPV4_LEN])
{
	for (size_t i = 0; i < IPV4_LEN; ++i) {
		if (pa1[i] != pa2[i])
			return 0;
	}
	return 1;
}

int is_mac_equal(const uint8_t pa1[ETH_ALEN], const uint8_t pa2[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i) {
		if (pa1[i] != pa2[i])
			return 0;
	}
	return 1;
}

/* return wheter the given addr is a hardware broadcast address */
int is_hbroadcast_addr(const uint8_t addr[ETH_ALEN])
{
	for (size_t i = 0; i < ETH_ALEN; ++i) {
		if (addr[i] != 255)
			return 0;	
	}
	return 1;
}

/* retreive IPv4 address and mac address of the requestes name interface */
int get_network_interface_addresses(char name[IF_NAMESIZE], uint8_t ipv4[IPV4_LEN], uint8_t mac[ETH_ALEN])
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifap_it;
	size_t ipmatch = 0, macmatch = 0;

	if (getifaddrs(&ifap) != 0)
		goto err;

	for (ifap_it = ifap; ifap_it != NULL; ifap_it = ifap_it->ifa_next)
	{
		if (strncmp(name, ifap_it->ifa_name, IF_NAMESIZE) == 0
			&& ifap_it->ifa_addr && ifap_it->ifa_addr->sa_family == AF_INET	/* if interface has an ipv4 */
			&& (IFF_LOOPBACK & ifap_it->ifa_flags) != IFF_LOOPBACK	/* and interface is not a loopback interface (lo) */
			&& (IFF_UP & ifap_it->ifa_flags) == IFF_UP)	/* and interface is up */
		{
			*(uint32_t*)ipv4 = *(uint32_t*)&(((struct sockaddr_in*)ifap_it->ifa_addr)->sin_addr);
			ipmatch += 1;
		}
		if (strncmp(name, ifap_it->ifa_name, IF_NAMESIZE) == 0
			&& ifap_it->ifa_addr && ifap_it->ifa_addr->sa_family == AF_PACKET	/* if interface is mac */
			&& (IFF_LOOPBACK & ifap_it->ifa_flags) != IFF_LOOPBACK	/* and interface is not a loopback interface (lo) */
			&& (IFF_UP & ifap_it->ifa_flags) == IFF_UP)	/* and interface is up */
		{
			for (int i = 0; i < ETH_ALEN; ++i)
				mac[i] = ((struct sockaddr_ll*)ifap_it->ifa_addr)->sll_addr[i];
			macmatch += 1;
		}
	}

	freeifaddrs(ifap);
	if (ipmatch == 1 && macmatch == 1)
		return 0;
err:
	return 1;
}

/* put in name the 1st network interface which match some condition */
int get_network_interface_name(char name[IFNAMSIZ])
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifap_it;

	if (getifaddrs(&ifap) != 0)
		goto err;

	for (ifap_it = ifap; ifap_it != NULL; ifap_it = ifap_it->ifa_next)
	{
		if (ifap_it->ifa_addr && ifap_it->ifa_addr->sa_family == AF_INET	/* if interface has an ipv4 */
			&& (IFF_LOOPBACK & ifap_it->ifa_flags) != IFF_LOOPBACK	/* and interface is not a loopback interface (lo) */
			&& (IFF_UP & ifap_it->ifa_flags) == IFF_UP)	/* and interface is up */
		{
			strncpy(name, ifap_it->ifa_name, IFNAMSIZ);
			break;
		}
	}

	freeifaddrs(ifap);
	if (ifap_it != NULL)
		return 0;
err:
	return 1;
}