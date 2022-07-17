#include <stdio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

#include "define.h"
#include "utils.h"

/* retreive IPv4 address and mac address of the requestes name interface */
int get_network_interface_addresses(char name[IF_NAMESIZE], uint8_t ipv4[IPV4_LEN], uint8_t mac[ETH_ALEN], uint8_t netmask[ETH_ALEN])
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifap_it;
	char ipchoice = 'y', macchoice = 'y'; /* y or n used if multiple address */
	size_t ipmatch = 0, macmatch = 0;

	if (getifaddrs(&ifap) != 0)
		goto err;

	for (ifap_it = ifap; ifap_it != NULL; ifap_it = ifap_it->ifa_next)
	{
		if (strncmp(name, ifap_it->ifa_name, IF_NAMESIZE) == 0
			&& ifap_it->ifa_addr && ifap_it->ifa_addr->sa_family == AF_INET	/* if interface has an ipv4 */
			&& (IFF_LOOPBACK & ifap_it->ifa_flags) != IFF_LOOPBACK	/* and interface is not a loopback interface (lo) */
			&& (IFF_UP & ifap_it->ifa_flags) == IFF_UP)	/* and interface is up */
		{
			/* if we already read an ipv4 ask the user if he wants to use the new instead */
			if (ipmatch >= 1) {
				uint8_t tmp[IPV4_LEN];
				*(uint32_t*)tmp = *(uint32_t*)&(((struct sockaddr_in*)ifap_it->ifa_addr)->sin_addr);
				ASK_OLD_OR_NEW_IP(&ipchoice, name, ipv4, tmp);
			}
			/* hope you like ternaries :D */
			*(uint32_t*)ipv4 = (ipchoice == 'y' ? *(uint32_t*)&(((struct sockaddr_in*)ifap_it->ifa_addr)->sin_addr) : *(uint32_t*)ipv4);
			*(uint32_t*)netmask = *(uint32_t*)&(((struct sockaddr_in*)ifap_it->ifa_netmask)->sin_addr);
			ipchoice = 0;
			ipmatch += 1;
		}
		else if (strncmp(name, ifap_it->ifa_name, IF_NAMESIZE) == 0
			&& ifap_it->ifa_addr && ifap_it->ifa_addr->sa_family == AF_PACKET	/* if interface is mac */
			&& (IFF_LOOPBACK & ifap_it->ifa_flags) != IFF_LOOPBACK	/* and interface is not a loopback interface (lo) */
			&& (IFF_UP & ifap_it->ifa_flags) == IFF_UP)	/* and interface is up */
		{
			/* if we already read a macaddr ask the user if he wants to use the new instead */
			/* THIS PART HASNT BEEN TESTED IDK IF IT'S EVEN USEFUL */
			if (macmatch >= 1) {
				uint8_t tmp[ETH_ALEN];
				for (int i = 0; i < ETH_ALEN; ++i)
					mac[i] = ((struct sockaddr_ll*)ifap_it->ifa_addr)->sll_addr[i];
				ASK_OLD_OR_NEW_MAC(&macchoice, name, mac, tmp);
			}
			for (int i = 0; macchoice == 'y' && i < ETH_ALEN; ++i)
				mac[i] = ((struct sockaddr_ll*)ifap_it->ifa_addr)->sll_addr[i];
			macchoice = 0;
			macmatch += 1;
		}
	}

	freeifaddrs(ifap);
	if (ipmatch >= 1 && macmatch >= 1) {
		TELLIFACEINFO(name, ipv4, netmask, mac);
		return 0;
	}
err:
	ERROR_NO_INFO_FOR_IFACE(name);
	return 1;
}

/* 
** if ifacename is not empty, then check wether the current interface match ifacename
** main job is to confirm the existence of the supplied interface or to get one
*/
int get_network_interface(char ifacename[IF_NAMESIZE], uint8_t gateway_pa[IPV4_LEN])
{
	FILE *fd;
	char line[100] , *iface , *destination, *gateway, *saveptr;
	int ret = 1;

	fd = fopen("/proc/net/route" , "r");

	while(fgets(line , 100 , fd))
	{
		iface = strtok_r(line , " \t", &saveptr);
		destination = strtok_r(NULL , " \t", &saveptr);
		gateway = strtok_r(NULL , " \t", &saveptr);

		if(iface != NULL
		&& destination != NULL
		&& gateway != NULL
		&& strcmp(destination , "00000000") == 0
		&& (ifacename[0] == 0 ? 1 : strcmp(iface, ifacename) == 0))
		{
			strncpy(ifacename, iface, IF_NAMESIZE);
			*(uint32_t*)gateway_pa = strtol(gateway, NULL, 16);
			ret = 0;
			break;
		}
	}
	fclose(fd);
	if (ret != 0) {
		ifacename[0] == 0x0 ? (ERROR_NO_IFACE(NULL)) : (ERROR_NO_IFACE(ifacename));
		ERROR_NO_GATEWAY();
	}
	else {
		TELLIFACE(ifacename);
		TELLGATEWAY(gateway_pa)
	}
	return ret;
}

/* functions that print hang on while the nmap scan is running */
static void *print_nmap_running(void *argp)
{
	struct timeval stop, start;

	TELLHANGON();
	gettimeofday(&start, NULL);
	while (*(int*)argp == 1) {
		gettimeofday(&stop, NULL);
		/* if more than 5 seconds passed */
		if (((stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec > 5000000)) {
			TELLHANGON();
			gettimeofday(&start, NULL);
		}
		sleep(0.2);
	}
}

/* scan the network with arp request using nmap */
int nmapscan(uint8_t gateway_pa[IPV4_LEN], uint8_t netmask[IPV4_LEN])
{
	char command[128];
	FILE *fd;
	pthread_t thread; /* used to print hang on to stdout */
	int scan_status = 1;

	/* this ISNT portable at all but give me a simpler anwser than what's on this thread and i put it
	https://stackoverflow.com/questions/6657475/netmask-conversion-to-cidr-format-in-c */
	snprintf(command, 128, "nmap -PR -sn %hhu.%hhu.%hhu.%hhu/%d",
		gateway_pa[0] & netmask[0], gateway_pa[1] & netmask[1],
		gateway_pa[2] & netmask[2], gateway_pa[3] & netmask[3],
		__builtin_popcount(*(uint32_t*)netmask)
	);
	TELLSCAN(gateway_pa, netmask);

	fd = popen(command, "r");
	pthread_create(&thread, NULL, print_nmap_running, &scan_status);
	if ( fd ) {
		char line[256];
		while (!feof(fd)) {
			char *line = NULL;
			size_t size;
			getline(&line, &size, fd);
			// printf("%s\n", line);
			free(line);
		}
		pclose(fd);
	}
	scan_status = 0;
	pthread_join(thread, NULL);
	TELLDONESCANNING(2, 256);
}