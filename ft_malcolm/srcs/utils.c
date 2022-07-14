#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>

# include "define.h"

void print_mac_address(const uint8_t addr[ETH_ALEN])
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void print_ipv4_address(const uint8_t addr[IPV4_LEN])
{
	printf("%d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
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