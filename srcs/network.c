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
#include <math.h>

#include "define.h"
#include "utils.h"
#include "struct.h"

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
				uint8_t tmp[ETH_ALEN] = { 0x0 };
				for (size_t i = 0; i < ETH_ALEN; ++i)
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
		// netmask[2] = 255; // for testing, used to scan a smaller network
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
	return NULL;
}

void free_arp_scan(nmap_r **scan)
{
	for (size_t i = 0; scan && scan[i] != NULL; ++i) {
		if (scan[i]->vendor != NULL)
			free(scan[i]->vendor);
		if (scan[i]->vendor_extra != NULL)
			free(scan[i]->vendor_extra);
		free(scan[i]);
	}
	if (scan)
		free(scan);
}

nmap_r **parse_arp_scan(FILE *fd)
{
	char *line = NULL;
	size_t size = 0;
	uint32_t idx = 0;
	nmap_r **scan = NULL;
	nmap_r *current = NULL;

	while (getline(&line, &size, fd) > 0) {

		/* new host */
		if (strncmp("Nmap scan report for ", line, 21) == 0) {
			if (!(scan = realloc(scan, (idx + 2) * sizeof(nmap_r*))))
				{ ERROR_MALLOC(); goto err; }
			scan[idx + 1] = NULL;
			if (!(scan[idx] = calloc(1, sizeof(nmap_r))))
				{ ERROR_MALLOC(); goto err; }
			scan[idx]->idx = idx;
			current = scan[idx];
			sscanf(line, "Nmap scan report for %hhu.%hhu.%hhu.%hhu", &current->pa[0], &current->pa[1], &current->pa[2], &current->pa[3]);
			++idx;
		}
		/* fille the mac addr of the current host */
		if (strncmp("MAC Address: ", line, 13) == 0) {
			if (current == NULL)
				{ ERROR_NMAP(line); goto err; }
			sscanf(line, "MAC Address: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &current->ha[0], &current->ha[1], &current->ha[2], &current->ha[3],  &current->ha[4], &current->ha[5]);
			current = NULL;
		}
		free(line);
		line = NULL;
	}
	free(line);

	if (scan == NULL)
		ERROR_SCAN();
	return scan;

err:
	free_arp_scan(scan);
	return NULL;
}

/* scan the network with arp request using nmap */
nmap_r **nmapscan(struct arguments *arguments)
{
	char command[128];
	int is_first_scan = is_mac_empty(arguments->gateway_ha); // check wether the gateway ha is empty or not unlikely HA is 0:0:0...
	FILE *fd = NULL;
	pthread_t thread; /* used to print hang on to stdout */
	int scan_status = 1;
	nmap_r **scan = NULL; /* hold result of the arp nmap scan */

	/* this ISNT portable at all but give me a simpler anwser than what's on this thread and i put it
	https://stackoverflow.com/questions/6657475/netmask-conversion-to-cidr-format-in-c */
	snprintf(command, 128, "nmap -PR -sn -n %hhu.%hhu.%hhu.%hhu/%d 2>/dev/null",
		arguments->gateway_pa[0] & arguments->netmask[0], arguments->gateway_pa[1] & arguments->netmask[1],
		arguments->gateway_pa[2] & arguments->netmask[2], arguments->gateway_pa[3] & arguments->netmask[3],
		__builtin_popcount(*(uint32_t*)arguments->netmask)
	);
	TELLSCAN(arguments->gateway_pa, arguments->netmask);

	fd = popen(command, "r");
	// fd = fopen("res", "r");
	if (!fd)
		{ ERROR_POPEN(); goto err; }
	pthread_create(&thread, NULL, print_nmap_running, &scan_status);

	if (!(scan = parse_arp_scan(fd)))
		goto err;
	pclose(fd);

	scan_status = 0;
	pthread_join(thread, NULL);

	/* retreive the gateway HA from the scan and get the amount of entry */ 
	size_t i;
	for (i = 0; scan[i] != NULL; ++i) {
		if (is_ipv4_equal(scan[i]->pa, arguments->gateway_pa)) {
			scan[i]->gateway = 1;
			for (int j = 0; j < ETH_ALEN; ++j)
				arguments->gateway_ha[j] = scan[i]->ha[j];
		}
		if (is_ipv4_equal(scan[i]->pa, arguments->self_pa)) {
			scan[i]->self = 1;
			for (int j = 0; j < ETH_ALEN; ++j)
				scan[i]->ha[j] = arguments->self_ha[j];
		}
	}
	arguments->scanamount = i;

	TELLDONESCANNING(arguments->scanamount, (int)pow(2, ((32 - __builtin_popcount(*(uint32_t*)arguments->netmask)))));
	if (is_first_scan)
		TELLGATEWAYHA(arguments->gateway_ha);
	if (arguments->scanamount <= 2)
		NETWORK_EMPTY();
	return scan;

err:
	if (fd)
		pclose(fd);
	return NULL;
}
