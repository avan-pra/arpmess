#ifndef DEFINE_H
# define DEFINE_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE   "\x1b[37m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define ANSI_COLOR_BRIGHT_RED     "\x1b[91m"
#define ANSI_COLOR_BRIGHT_GREEN   "\x1b[92m"
#define ANSI_COLOR_BRIGHT_YELLOW  "\x1b[93m"
#define ANSI_COLOR_BRIGHT_BLUE    "\x1b[94m"
#define ANSI_COLOR_BRIGHT_MAGENTA "\x1b[95m"
#define ANSI_COLOR_BRIGHT_CYAN    "\x1b[96m"
#define ANSI_COLOR_BRIGHT_WHITE   "\x1b[97m"

# define IFACECOLOR ANSI_COLOR_BRIGHT_CYAN
# define IPV4COLOR ANSI_COLOR_BRIGHT_RED
# define MACCOLOR ANSI_COLOR_BRIGHT_YELLOW
# define NETMASKCOLOR ANSI_COLOR_BRIGHT_MAGENTA

# define PROG_NAME "arpmess"
# define SOCKET int
# define IPV4_LEN 4
// # define ETH_HLEN sizeof(eth)
# define ARP_HLEN sizeof(arp)
# define SAMPLE_INFO "["ANSI_COLOR_BRIGHT_BLUE"*"ANSI_COLOR_RESET"] "
# define SAMPLE_NEW "["ANSI_COLOR_BRIGHT_GREEN"+"ANSI_COLOR_RESET"] "
# define SAMPLE_ERROR "["ANSI_COLOR_BRIGHT_RED"-"ANSI_COLOR_RESET"] "

#ifndef SO_BINDTODEVICE
# define SO_BINDTODEVICE 0x19	/* for vscode */
#endif

# define TELLIFACE(IFACENAME) { printf("%sFound available interface "IFACECOLOR"%s"ANSI_COLOR_RESET"\n", SAMPLE_NEW, IFACENAME); }
# define TELLGATEWAY(GATEWAYPA) { printf("%sFound gateway protocol address "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\n", SAMPLE_NEW, GATEWAYPA[0], GATEWAYPA[1], GATEWAYPA[2], GATEWAYPA[3]); }
# define TELLIFACEINFO(IFACENAME, IPV4, MASK, MAC) { printf("%sFound netmask for network: "NETMASKCOLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\n%sFound ipv4 for interface "IFACECOLOR"%s"ANSI_COLOR_RESET": "IPV4COLOR"%d.%d.%d.%d"ANSI_COLOR_RESET"\n%sFound mac for interface "IFACECOLOR"%s"ANSI_COLOR_RESET": "MACCOLOR"%02x:%02x:%02x:%02x:%02x:%02x"ANSI_COLOR_RESET"\n", SAMPLE_NEW, MASK[0], MASK[1], MASK[2], MASK[3], SAMPLE_NEW, IFACENAME, IPV4[0], IPV4[1], IPV4[2], IPV4[3], SAMPLE_NEW, IFACENAME, MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]); }
# define TELLSCAN(IPV4, MASK) { printf("%susing nmap, arp scanning network "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"/"NETMASKCOLOR"%d"ANSI_COLOR_RESET"\n", SAMPLE_INFO, IPV4[0] & MASK[0], IPV4[1] & MASK[1], IPV4[2] & MASK[2], IPV4[3] & MASK[3], __builtin_popcount(*(uint32_t*)MASK)); }
# define TELLHANGON() { printf("%snmap scan running, hang on...\n", SAMPLE_INFO); }
# define TELLDONESCANNING(N, NT) { printf("%sdone scanning %d out of %d hosts are up\n", SAMPLE_INFO, N, NT); }

# define TELLEXITING() { printf("Exiting program...\n"); }

# define ERROR_UID(UID, PROG_PATH) { fprintf(stderr, "%sexpected uid %d to run %s, got %d\n", SAMPLE_ERROR, 0, PROG_PATH, UID); }
# define ERROR_EXIT() { fprintf(stderr, "%s"ANSI_COLOR_RED"Exiting...\n"ANSI_COLOR_RESET, SAMPLE_ERROR); }
# define ERROR_NO_IFACE(IFACENAME) { IFACENAME == NULL ? fprintf(stderr, "%scould not find a fitting interface\n", SAMPLE_ERROR) : printf("%sinterface %s not found or not fitting\n", SAMPLE_ERROR, IFACENAME); }
# define ERROR_NO_GATEWAY() { fprintf(stderr, "%scould not find a gateway\n", SAMPLE_ERROR); }
# define ERROR_NO_INFO_FOR_IFACE(IFACENAME) { fprintf(stderr, "%scould not find ipv4 and harware address of interface %s\n", SAMPLE_ERROR, IFACENAME); }

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