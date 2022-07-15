#ifndef DEFINE_H
# define DEFINE_H

# define SOCKET int
# define IPV4_LEN 4
// # define ETH_HLEN sizeof(eth)
# define ARP_HLEN sizeof(arp)
# define ERROR_SAMPLE "Error: "
# define PROG_NAME "ft_malcolm"

# define USAGE() { printf("Usage: <spoofed_ip> <spoofed_mac> <origin_ip> <origin_mac>\n"); }
# define BADUID(UID) { fprintf(stderr, "%sexpected uid %d to run %s, got %d\n", ERROR_SAMPLE, 0, PROG_NAME, UID); }
# define BAD_IP_ARGUMENT(IP) ( fprintf(stderr, "%sunknown host or invalid IP address: (%s)\n", ERROR_SAMPLE, IP) )
# define BAD_HDW_ARGUMENT(MAC) ( fprintf(stderr, "%sunknown host or invalid IP address: (%s)\n", ERROR_SAMPLE, MAC) )


#ifndef SO_BINDTODEVICE
# define SO_BINDTODEVICE 0x19	/* for vscode */
#endif

# include "struct.h"

#endif