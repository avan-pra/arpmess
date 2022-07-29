#include <unistd.h>
#include <stdlib.h>
#include "utils.h"
#include "struct.h"

static int interactivemode(nmap_r **scan, struct arguments *arguments)
{
	int action;

	while (1)
	{
		action = ask_action();

		/* 1 */
		if (action == ACTION_ONE) {
			long long hostidx = ask_index(scan, arguments);
			if (hostidx == ACTION_EXIT)
				break;
			if (hostidx == ACTION_RETURN)
				continue;
			if (start_attack_one(arguments, scan[hostidx]) != 0)
				goto err;
			continue;
		}
		/* 2 */
		else if (action == ACTION_SOME) {
			ERROR_NO_YET_IMPLEMENTED();
		}
		/* 3 */
		else if (action == ACTION_ALL) {
			if (arguments->scanamount - 2 > 0) {
				if (start_attack_all(arguments, scan) != 0)
					goto err;
			}
			else
				NETWORK_EMPTY();
		}
		/* 4 */
		else if (action == ACTION_SPOOF) {
			if (mitm_requirements() == -1) // only on critical error returns -1
				goto err;
			long long hostidx = ask_index(scan, arguments);
			if (hostidx == ACTION_EXIT)
				break;
			if (hostidx == ACTION_RETURN)
				continue;
			if (arpspoof(arguments, scan, hostidx) != 0)
				goto err;
			continue;
		}
		/* L */
		else if (action == ACTION_LIST) {
			PRINT_SCAN_LIST(scan);
		}
		/* S */
		else if (action == ACTION_SCAN) {
			free_arp_scan(scan);
			TELLRESCAN();
			if (!(scan = nmapscan(arguments))) 
				goto err;
			if (fill_vendor_from_manuf_file(scan) != 0)
				goto err;
		}
		/* E */
		else if (action == ACTION_EXIT)
			break;
	}
	return 0;
err:
	return 1;
}

static int kickmode(nmap_r **scan, struct arguments *arguments)
{
	if (arguments->scanamount - 2 > 0) {
		printf("\n");
		if (start_attack_all(arguments, scan) != 0)
			goto err;
	}
	else if (arguments->target_list != NULL) {
		ERROR_NO_TARGET_SUPPLIED();
	}
	else {
		NETWORK_EMPTY();
	}
	return 0;
err:
	return 1;
}

int main(int argc, char **argv)
{
	struct arguments arguments = { 0x0 };
	nmap_r **scan = NULL; /* hold result of the arp nmap scan */
	int action;

	arguments.ppm = 12; /* default value of packet sent per minute */
	arguments.sys_netmask = 1;
	argparse(argc, argv, &arguments);

	if (getuid() != 0)
	{ ERROR_UID(getuid(), argv[0]); goto err; }

	/* we are getting network interface info in two rounds to */
	/* confirm the existence of the interface specified by the user or get one
	retreive gateway protocol address */
	if (get_network_interface(arguments.ifacename, arguments.gateway_pa) != 0)
		goto err;//error no iface found
	/* get self ipv4, self mac addr, netmask of the network */
	if (get_network_interface_addresses(&arguments) != 0)
		goto err;//error no hardware addr or protocol address for specified interface

	/* will only scan if no target are specified */
	if (!(scan = nmapscan(&arguments))) 
		goto err;

	if (fill_vendor_from_manuf_file(scan) != 0)
		goto err;

	TELLHEADER();

	if (arguments.mode == INTERACTIVE) {
		if (interactivemode(scan, &arguments) != 0)
			goto err;
	}

	if (arguments.mode == KICK) {
		if (arguments.target_list != NULL) {
			if (kickmode(scan, &arguments) != 0)
				goto err;
		}
		else
			ERROR_NO_TARGET_SUPPLIED();
	}

	if (arguments.mode == SPOOF) {
		ERROR_NO_YET_IMPLEMENTED();
	}

	if (arguments.nmapflags != NULL)
		free(arguments.nmapflags);
	free_arp_scan(scan);
	return 0;

err:
	if (scan)
		free_arp_scan(scan);
	if (arguments.nmapflags != NULL)
		free(arguments.nmapflags);
	ERROR_EXIT();
	return 1;
}
