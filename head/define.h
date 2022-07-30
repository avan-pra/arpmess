#ifndef DEFINE_H
# define DEFINE_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE   "\x1b[37m"
#define ANSI_COLOR_BLACK   "\x1b[30m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define ANSI_COLOR_BRIGHT_RED     "\x1b[91m"
#define ANSI_COLOR_BRIGHT_GREEN   "\x1b[92m"
#define ANSI_COLOR_BRIGHT_YELLOW  "\x1b[93m"
#define ANSI_COLOR_BRIGHT_BLUE    "\x1b[94m"
#define ANSI_COLOR_BRIGHT_MAGENTA "\x1b[95m"
#define ANSI_COLOR_BRIGHT_CYAN    "\x1b[96m"
#define ANSI_COLOR_BRIGHT_WHITE   "\x1b[97m"

#define ANSI_COLOR_256_ORANGE "\x1b[38;5;214m"
#define ANSI_COLOR_256_PINK   "\x1b[38;5;198m"

# define IFACECOLOR ANSI_COLOR_BRIGHT_CYAN
# define IPV4COLOR ANSI_COLOR_BRIGHT_RED
# define MACCOLOR ANSI_COLOR_BRIGHT_YELLOW
# define NETMASKCOLOR ANSI_COLOR_BRIGHT_MAGENTA
# define VENDORCOLOR ANSI_COLOR_BRIGHT_GREEN
# define VENDORCOLOREXTRA ANSI_COLOR_BRIGHT_GREEN

# define TERMPROMPT ANSI_COLOR_BRIGHT_GREEN

# define WEBSITE "https://avan.sh"
# define PROGNAME "arpmess"
# define PROMPT TERMPROMPT""PROGNAME""ANSI_COLOR_RESET" "ANSI_COLOR_BRIGHT_WHITE"Ɛ> "ANSI_COLOR_RESET
# define SOCKET int
# define IPV4_LEN 4
// # define ETH_HLEN sizeof(eth)
# define ARP_HLEN sizeof(arp)
# define SAMPLE_INFO "["ANSI_COLOR_BRIGHT_BLUE"*"ANSI_COLOR_RESET"] "
# define SAMPLE_NEW "["ANSI_COLOR_BRIGHT_GREEN"+"ANSI_COLOR_RESET"] "
# define SAMPLE_ERROR "["ANSI_COLOR_BRIGHT_RED"-"ANSI_COLOR_RESET"] "
# define ACTION_KICK_SOME '1'
# define ACTION_KICK_ALL '2'
# define ACTION_SPOOF_SOME '3'
# define ACTION_SPOOF_ALL '4'
# define ACTION_EXIT -1
# define ACTION_RETURN -2
# define ACTION_SCAN -3
# define ACTION_LIST -4
# define INTERACTIVE 0
# define KICK 1
# define SPOOF 2

typedef __uint128_t uint128_t;

#ifndef SO_BINDTODEVICE
# define SO_BINDTODEVICE 0x19	/* for vscode */
#endif

# define TELLHEADER() { printf("\n"TERMPROMPT""PROGNAME""ANSI_COLOR_RESET""ANSI_COLOR_BRIGHT_WHITE": A tool by Arth ("WEBSITE")\n"); }

# define TELLIFACE(IFACENAME) { printf("%sFound available interface "IFACECOLOR"%s"ANSI_COLOR_RESET"\n", SAMPLE_NEW, IFACENAME); }
# define TELLGATEWAY(GATEWAYPA) { printf("%sFound gateway protocol address "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\n", SAMPLE_NEW, GATEWAYPA[0], GATEWAYPA[1], GATEWAYPA[2], GATEWAYPA[3]); }
# define TELLIFACEINFO(IFACENAME, IPV4, MASK, MAC) { printf("%sUsing netmask: "NETMASKCOLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\n%sFound ipv4 for interface "IFACECOLOR"%s"ANSI_COLOR_RESET": "IPV4COLOR"%d.%d.%d.%d"ANSI_COLOR_RESET"\n%sFound mac for interface "IFACECOLOR"%s"ANSI_COLOR_RESET": "MACCOLOR"%02x:%02x:%02x:%02x:%02x:%02x"ANSI_COLOR_RESET"\n", SAMPLE_INFO, MASK[0], MASK[1], MASK[2], MASK[3], SAMPLE_NEW, IFACENAME, IPV4[0], IPV4[1], IPV4[2], IPV4[3], SAMPLE_NEW, IFACENAME, MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]); }
# define TELLIFACEINFOSYSTEM(IFACENAME, IPV4, MASK, MAC) { printf("%sFound netmask for network: "NETMASKCOLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\n%sFound ipv4 for interface "IFACECOLOR"%s"ANSI_COLOR_RESET": "IPV4COLOR"%d.%d.%d.%d"ANSI_COLOR_RESET"\n%sFound mac for interface "IFACECOLOR"%s"ANSI_COLOR_RESET": "MACCOLOR"%02x:%02x:%02x:%02x:%02x:%02x"ANSI_COLOR_RESET"\n", SAMPLE_NEW, MASK[0], MASK[1], MASK[2], MASK[3], SAMPLE_NEW, IFACENAME, IPV4[0], IPV4[1], IPV4[2], IPV4[3], SAMPLE_NEW, IFACENAME, MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]); }
# define TELLSCAN(IPV4, MASK) { printf("%sUsing nmap, arp scanning network "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"/"NETMASKCOLOR"%d"ANSI_COLOR_RESET"\n", SAMPLE_INFO, IPV4[0] & MASK[0], IPV4[1] & MASK[1], IPV4[2] & MASK[2], IPV4[3] & MASK[3], __builtin_popcount(*(uint32_t*)MASK)); }
# define TELLSCANTARGET(IPV4, TARGETLIST) { printf("%sUsing nmap, arp scanning "IPV4COLOR"%hhu.%hhu.%hhu.%hhu %s"ANSI_COLOR_RESET"\n", SAMPLE_INFO, IPV4[0], IPV4[1], IPV4[2], IPV4[3], TARGETLIST); }
# define TELLHANGON() { printf("%snmap scan running, hang on...\n", SAMPLE_INFO); }
# define TELLDONESCANNING(N, NT) { printf("%sDone scanning, %d out of %d hosts are up\n", SAMPLE_INFO, N, NT); }
# define TELLGATEWAYHA(HA) { printf("%sFound gateway hardware address: "MACCOLOR"%02x:%02x:%02x:%02x:%02x:%02x"ANSI_COLOR_RESET"\n", SAMPLE_NEW, HA[0], HA[1], HA[2], HA[3], HA[4], HA[5]); }
# define TELLSOCKETSUCCESS(IFACENAME) { printf("%sSuccessfully binded raw socket to interface "IFACECOLOR"%s"ANSI_COLOR_RESET"\n", SAMPLE_INFO, IFACENAME); }
# define TELLNUKINGTARGET(TARGETIP, GATEWAYIP, SELFMAC) { fprintf(stdout, "%sNuking target "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET" with arp reply packet: "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET" is at "MACCOLOR"%02x:%02x:%02x:%02x:%02x:%02x"ANSI_COLOR_RESET"\n", SAMPLE_INFO, TARGETIP[0], TARGETIP[1], TARGETIP[2], TARGETIP[3], GATEWAYIP[0], GATEWAYIP[1], GATEWAYIP[2], GATEWAYIP[3], SELFMAC[0], SELFMAC[1], SELFMAC[2], SELFMAC[3], SELFMAC[4], SELFMAC[5]); }
# define TELLSTOPATTACK() { printf("%sStopped the spoofing, returning to main menu...\n", SAMPLE_INFO); }
# define TELLRESCAN() { printf("%sRescanning...\n", SAMPLE_INFO); }
# define TELLRESTORINGMAC() { printf("%sRestoring arp table of the victim, ctrl+c when you feel like the arp table is restored\n", SAMPLE_INFO); }
# define TELLACTIVATEIPFORWARD() { printf("%sIP forward was successfully activated\n", SAMPLE_INFO); }
# define TELLDEACTIVATEIPFORWARD() { printf("%sIP forward was successfully desactivated\n", SAMPLE_INFO); }
# define TELLIPFORWARDDEFAULT(C) { printf("%s/proc/sys/net/ipv4/ip_forward defaults to value: %c\n", SAMPLE_INFO, C); }

# define TELLEXITING() { printf("Exiting program...\n"); }

# define ERROR_UID(UID, PROG_PATH) { fprintf(stderr, "%sExpected uid %d to run %s, got %d\n", SAMPLE_ERROR, 0, PROG_PATH, UID); }
# define ERROR_EXIT() { fprintf(stderr, "%s"ANSI_COLOR_RED"Exiting..."ANSI_COLOR_RESET"\n", SAMPLE_ERROR); }
# define ERROR_NO_IFACE(IFACENAME) { IFACENAME == NULL ? fprintf(stderr, "%sCould not find a fitting interface\n", SAMPLE_ERROR) : printf("%sinterface %s not found or not fitting\n", SAMPLE_ERROR, (char*)IFACENAME); }
# define ERROR_NO_GATEWAY() { fprintf(stderr, "%sCould not find a gateway\n", SAMPLE_ERROR); }
# define ERROR_NO_INFO_FOR_IFACE(IFACENAME) { fprintf(stderr, "%sCould not find ipv4 and harware address of interface %s\n", SAMPLE_ERROR, IFACENAME); }
# define ERROR_MALLOC() { fprintf(stderr, "%smalloc() returned NULL\n", SAMPLE_ERROR); }
# define ERROR_POPEN() { fprintf(stderr, "%spopen() returned NULL\n", SAMPLE_ERROR); }
# define ERROR_NMAP(LINE) { fprintf(stderr, "%sThe nmap scan returned an incomprehensible line: |%s|", SAMPLE_ERROR, LINE); }
# define ERROR_SCAN() { fprintf(stderr, "%sThere was a prolem with the nmap scan, is the tool installed ?\n", SAMPLE_ERROR); }
# define ERROR_UNRECOGNIZED_CHAR_ASK(CHAR) { fprintf(stderr, "%sUnrecognized selected choice: %c\n", SAMPLE_ERROR, CHAR); }
# define ERROR_UNRECOGNIZED_UINTEGER_ASK(INT) { fprintf(stderr, "%sUnrecognized selected choice: %u\n", SAMPLE_ERROR, INT); }
# define ERROR_UNRECOGNIZED_LONG_ASK(INT) { fprintf(stderr, "%sUnrecognized selected choice: %lld\n", SAMPLE_ERROR, INT); }
# define ERROR_CANT_SELECT_SELF_OR_GATEWAY() { fprintf(stderr, "%sYou can't poison neither the gateway nor yourself\n", SAMPLE_ERROR); }
# define ERROR_NO_YET_IMPLEMENTED() { fprintf(stderr, "%sThis feature hasnt been implemented yet\n", SAMPLE_ERROR); }
# define ERROR_NO_MANUF_FILE() { fprintf(stderr, "%smanuf file not found, information about vendor won't be shown, run `make vendor` to download\n", SAMPLE_ERROR); }
# define ERROR_SOCKET_DENIED() { fprintf(stderr, "%scould not create a raw socket\n", SAMPLE_ERROR); }
# define ERROR_SOCKET_MODIFY_DENIED(IFACENAME) { fprintf(stderr, "%ssuccessfully create a socket but could not bind it to device %s using setsockopt()\n", SAMPLE_ERROR, IFACENAME); }
# define ERROR_SEND() { fprintf(stderr, "%srsendto() returned -1\n", SAMPLE_ERROR); }
# define ERROR_RECV() { fprintf(stderr, "%srecvfrom() returned -1\n", SAMPLE_ERROR); }
# define ERROR_PACKET_PER_MINUTE() { fprintf(stderr, "%sAmount of packets sent per minute must be >= 0, currently: %d\n", SAMPLE_ERROR, arguments->ppm); }
# define NETWORK_EMPTY() { fprintf(stderr, "\n%sWARNING: only you and your gateway are on the network, NO OPTIONS ARE AVAILABLE, try rescanning\n", SAMPLE_ERROR); }
# define ERROR_NO_IP_FORWARD() { fprintf(stderr, "\n%sWARNING: ip forward is not enable, run `echo 1 | tee /proc/sys/net/ipv4/ip_forward` in a root shell to perform the mitm\n", SAMPLE_ERROR); }
# define ERROR_TARGET_UNKNOWN_FORMAT(TARGET) { fprintf(stderr, "%sUnrecognized target %s, only private ipv4 are valid (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)\n", SAMPLE_ERROR, TARGET); }
# define ERROR_NO_TARGET_SUPPLIED() { fprintf(stderr, "\n%sA target list is needed for the current mode\n", SAMPLE_ERROR); }
# define ERROR_UNKNOWN_MODE(MODE) { fprintf(stderr, "%sUnknown mode %s, uppercase ? INTERACTIVE/KICK/SPOOF\n", SAMPLE_ERROR, MODE); }
# define ERROR_PPM_HIGH() { fprintf(stderr, "%sarp reply packets will be sent as fast as possible, care\n", SAMPLE_ERROR); }
# define ERROR_CANT_MODIFY_IP_FORWARD() { fprintf(stderr, "%s/proc/sys/net/ipv4/ip_forward can't be modify for some reason\n", SAMPLE_ERROR); }

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

# define ASK_ATTACK_TYPE() { printf("\n%sChoose an option from the menu:\n\
\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"1"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" Kick "ANSI_COLOR_BRIGHT_WHITE"SOME"ANSI_COLOR_RESET" Off\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"2"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" Kick "ANSI_COLOR_BRIGHT_WHITE"ALL"ANSI_COLOR_RESET" Off\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"3"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" Spoof "ANSI_COLOR_BRIGHT_WHITE"SOME"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"4"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" Spoof "ANSI_COLOR_BRIGHT_WHITE"ALL"ANSI_COLOR_RESET"\n\
\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"L"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" List hosts"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"S"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" reScan"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"E"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Exit"ANSI_COLOR_RESET"\n\
\n\
"PROMPT, SAMPLE_INFO);\
}

# include "struct.h"

#endif