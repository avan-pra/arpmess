#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netdb.h>

#include "define.h"
#include "struct.h"

/* this function transform a string (IPv4 / hostname / decimal ipv4 named str) to an uint8_t[4] (named buf) */ 
int fill_ipv4_from_string(char *str, uint8_t buf[IPV4_LEN])
{
	struct addrinfo hint = { 0x0 };
	struct addrinfo *infos = 0x0;
	struct addrinfo *save_infos = 0x0;
	uint32_t addr;
	char *ptr = str;
	char ipstr[INET_ADDRSTRLEN];

	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	getaddrinfo(str, "", &hint, &infos);

	/* keep a pointer to infos to free it later on */
	save_infos = infos;

	/* loop through getaddrinfo return, stopping at an ipv4 address */
	while (infos != NULL && infos->ai_family != AF_INET)
		infos = infos->ai_next;

	/* we did not found an ipv4 address OR the supplied hostname is shit maybe it's a decimal ipv4 */
	if (infos == NULL) {
		char check_char;
		int sres = 0;

		sres = sscanf(str, "%u%c", &addr, &check_char);
		if (sres != 1)
			goto bad_ip_argument;
		printf("%u\n", addr);
	}
	else
		addr = *((uint32_t*)&(((struct sockaddr_in *)infos->ai_addr)->sin_addr));

	/* put a readble ipv4 addr in ipstr */
	snprintf(ipstr, sizeof(ipstr), "%hhd.%hhd.%hhd.%hhd\n",
		((uint8_t*)&(addr))[0],
		((uint8_t*)&(addr))[1],
		((uint8_t*)&(addr))[2],
		((uint8_t*)&(addr))[3]
	);
	// inet_ntop(infos->ai_family, &((struct sockaddr_in *)infos->ai_addr)->sin_addr, ipstr, sizeof(ipstr)); // not fucking allowed so doing one myself
	ptr = ipstr;

	/* roll back infos to free it */
	infos = save_infos;

	/* fill buf with the ipv4 address supplied OR the one found by getaddrinfo */
	sscanf(ptr, "%hhd.%hhd.%hhd.%hhd", &buf[0], &buf[1], &buf[2], &buf[3]);

	if (infos != NULL)
		freeaddrinfo(infos);
	return 0;

bad_ip_argument:
	BAD_IP_ARGUMENT(str);
	if (save_infos != NULL)
		freeaddrinfo(save_infos);
	return 1;
}

/* this function transform a string (hardware address named str) to an uint8_t[6] (named buf) */ 
int fill_mac_from_string(char *str, uint8_t buf[ETH_ALEN])
{
	uint8_t cpy[ETH_ALEN] = { 0x0 };
	char check_char = 0;
	int sres = 0x0;

	sres = sscanf(str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx%c", &cpy[0], &cpy[1], &cpy[2], &cpy[3], &cpy[4], &cpy[5], &check_char);
	if (sres != 6)
		goto bad_hdw_argument;
	memcpy(buf, cpy, sizeof(cpy));
	return 0;

bad_hdw_argument:
	BAD_HDW_ARGUMENT(str);
	return 1;
}

int fill_arg(char **argv, attack *attacks_infos)
{
	if (fill_ipv4_from_string(argv[1], attacks_infos->spoofed_pa) != 0)
		return 1;
	if (fill_mac_from_string(argv[2], attacks_infos->spoofed_ha) != 0)
		return 1;
	if (fill_ipv4_from_string(argv[3], attacks_infos->target_pa) != 0)
		return 1;
	if (fill_mac_from_string(argv[4], attacks_infos->target_ha) != 0)
		return 1;

	return 0;
}
