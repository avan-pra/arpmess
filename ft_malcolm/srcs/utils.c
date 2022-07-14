#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>

/* return wheter the given addr is a hardware broadcast address */
int is_hbroadcast_addr(uint8_t addr[6])
{
	for (size_t i = 0; i < 6; ++i) {
		if (addr[i] != 255)
			return 0;	
	}
	return 1;
}

/* put in name the 1st network interface which has ........ */
int get_network_interface_name(char name[IFNAMSIZ])
{
	struct ifaddrs *ifap;

	if (getifaddrs(&ifap) != 0)
		goto err;

	freeifaddrs(ifap);

	printf("yoooooooo\n");

	return 0;
err:
	return 1;
}