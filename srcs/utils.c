#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "define.h"

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
