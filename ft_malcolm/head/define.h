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
# define BAD_IP_ARGUMENT(IP) { fprintf(stderr, "%sunknown host or invalid IP address: (%s)\n", ERROR_SAMPLE, IP); }
# define BAD_HDW_ARGUMENT(MAC) { fprintf(stderr, "%sunknown host or invalid IP address: (%s)\n", ERROR_SAMPLE, MAC); }
# define NO_IFACE_AVAILABLE() { fprintf(stderr, "%scould not find an ipv4 upped network interface\n", ERROR_SAMPLE); }
# define NO_INFO_FOR_IFACE(IFACENAME) { fprintf(stderr, "%scould not find ipv4 and harware address of interface %s\n", ERROR_SAMPLE, IFACENAME); }
# define SOCKET_DENIED() { fprintf(stderr, "%scould not create a raw socket\n", ERROR_SAMPLE); }
# define SOCKET_MODIFY_DENIED(IFACENAME) { fprintf(stderr, "%ssuccessfully create a socket but could not bind it to device %s using setsockopt()\n", ERROR_SAMPLE, IFACENAME); }
# define RECVERROR() { fprintf(stderr, "%srecvfrom() returned -1\n", ERROR_SAMPLE); }
# define SENDERROR() { fprintf(stderr, "%srsendto() returned -1\n", ERROR_SAMPLE); }

# define TELLIFACE(IFACENAME) { printf("Found available interface %s\n", IFACENAME); }
# define TELLIFACEINFO(IFACENAME, IPV4, MAC) { printf("%s:\n\t- ipv4:\t%d.%d.%d.%d\n\t- mac:\t%02x:%02x:%02x:%02x:%02x:%02x\n", IFACENAME, IPV4[0], IPV4[1], IPV4[2], IPV4[3], MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]); }
# define TELLSTARTLISTENER(IFACENAME) { printf("Listening for ARP requests on iface %s\n", IFACENAME); }
# define TELLARPMATCH(IPV4, MAC) { printf("An ARP request has been broadcast by our target.\n\tmac address of request:\t%02x:%02x:%02x:%02x:%02x:%02x\n\tIP address of request:\t%d.%d.%d.%d\n", IPV4[0], IPV4[1], IPV4[2], IPV4[3], MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]); }
# define TELLSENDARPREPLY(IPV4, MAC) { printf("Sending ARP reply packet:\n\n\t%d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n\n", IPV4[0], IPV4[1], IPV4[2], IPV4[3], MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]); }
# define TELLARPREPLYSENT() { printf("ARP reply has been sent to target\n"); }
# define TELLEXITING() { printf("Exiting program...\n"); }

#ifndef SO_BINDTODEVICE
# define SO_BINDTODEVICE 0x19	/* for vscode */
#endif

# include "struct.h"

#endif