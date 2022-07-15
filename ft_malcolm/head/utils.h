#ifndef UTILS_H
# define UTILS_H

#include <stdint.h>
#include <net/if.h>
# include <linux/if_ether.h>

# include "define.h"

int is_hbroadcast_addr(const uint8_t addr[ETH_ALEN]);
int get_network_interface_name(char name[IFNAMSIZ]);
int is_ipv4_equal(const uint8_t pa1[IPV4_LEN], const uint8_t pa2[IPV4_LEN]);
int is_mac_equal(const uint8_t pa1[ETH_ALEN], const uint8_t pa2[ETH_ALEN]);
void print_mac_address(const uint8_t addr[ETH_ALEN]);
void print_ipv4_address(const uint8_t addr[IPV4_LEN]);
void copy_ipv4(uint8_t dest[IPV4_LEN], const uint8_t src[IPV4_LEN]);
void copy_mac(uint8_t dest[ETH_ALEN], const uint8_t src[ETH_ALEN]);

#endif
