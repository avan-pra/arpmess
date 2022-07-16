#ifndef DEFINE_H
# define DEFINE_H

# define SOCKET int
# define IPV4_LEN 4
// # define ETH_HLEN sizeof(eth)
# define ARP_HLEN sizeof(arp)
# define ERROR_SAMPLE "Error: "

#ifndef SO_BINDTODEVICE
# define SO_BINDTODEVICE 0x19	/* for vscode */
#endif

# define ASK_OLD_OR_NEW_IP(uchoice, name, old, new) {\
	printf("More than 1 ipv4 have been detected for the selected interface %s\n\
\told: %d.%d.%d.%d\n\
\tnew: %d.%d.%d.%d\n", name, old[0], old[1], old[2], old[3], new[0], new[1], new[2], new[3]);\
	while (*uchoice != 'y' && *uchoice != 'n') {\
		printf("use new ? (y/n)\n");\
		scanf(" %c", uchoice);\
	}\
}
# define ASK_OLD_OR_NEW_MAC(uchoice, name, old, new) {\
	printf("More than 1 ipv4 have been detected for the selected interface %s\n\
\told: %02x:%02x:%02x:%02x:%02x:%02x\n\
\tnew: %02x:%02x:%02x:%02x:%02x:%02x\n", name, old[0], old[1], old[2], old[3], old[4], old[5], new[0], new[1], new[2], new[3], new[4], new[5]);\
	while (*uchoice != 'y' && *uchoice != 'n') {\
		printf("use new ? (y/n)\n");\
		scanf(" %c", uchoice);\
	}\
}

# include "struct.h"

#endif