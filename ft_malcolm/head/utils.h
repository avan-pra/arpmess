#ifndef UTILS_H
# define UTILS_H

#include <stdint.h>
#include <net/if.h>

int is_hbroadcast_addr(uint8_t addr[6]);
int get_network_interface_name(char name[IFNAMSIZ]);

#endif
