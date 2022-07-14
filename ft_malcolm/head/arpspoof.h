#ifndef ARPSPOOF_H
# define ARPSPOOF_H

# include <net/if.h>
# include "define.h"
# include "struct.h"

SOCKET initiate_socket_for_arp(char ifacename[IFNAMSIZ]);
int arpspoof(SOCKET iface, const attack *attacks_infos);

#endif