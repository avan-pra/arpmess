#include <unistd.h>
#include <stdlib.h>
#include "utils.h"
#include "struct.h"

static int interactivemode(nmap_r ***scan, struct arguments *arguments)
{
	int action;
	char *list = NULL; // malloc input of user to attack 1,2,3 etc

	while (1)
	{
		action = ask_action();
		if (list != NULL) {
			free(list);
			list = NULL;
		}

		/* if no one on the network, action > 0 are attack */
		if (action > 0 && arguments->scanamount - 2 <= 0) {
			printf("\n");
			WARNING_NETWORK_EMPTY();
		}
		/* 1 */
		else if (action == ACTION_KICK_SOME) {
			long long hostidx = ask_index_list(*scan, &list);
			if (hostidx == 1) // malloc error
				goto err;
			if (hostidx == ACTION_EXIT) {
				free(list);
				break;
			}
			if (hostidx == ACTION_RETURN)
				continue;
			if (start_attack_some(arguments, *scan, list) != 0)
				goto err;
			continue;
		}
		/* 2 */
		else if (action == ACTION_KICK_ALL) {
			if (start_attack_some(arguments, *scan, NULL) != 0)
				goto err;
		}
		/* 3 */
		else if (action == ACTION_SPOOF_SOME) {
			long long hostidx = ask_index_list(*scan, &list);
			if (hostidx == 1) // malloc error
				goto err;
			if (hostidx == ACTION_EXIT) {
				free(list);
				break;
			}
			if (hostidx == ACTION_RETURN)
				continue;
			if (arpspoof_some(arguments, *scan, list) != 0)
				goto err;
			continue;
		}
		/* 4 */
		else if (action == ACTION_SPOOF_ALL) {
			if (arpspoof_some(arguments, *scan, NULL) != 0)
				goto err;
		}
		/* 5 */
		else if (action == ACTION_RESTORE_SOME) {
			long long hostidx = ask_index_list(*scan, &list);
			if (hostidx == 1) // malloc error
				goto err;
			if (hostidx == ACTION_EXIT) {
				free(list);
				break;
			}
			if (hostidx == ACTION_RETURN)
				continue;
			if (restore_some(arguments, *scan, list) != 0)
				goto err;
			continue;
		}
		/* 6 */
		else if (action == ACTION_RESTORE_ALL) {
			if (restore_some(arguments, *scan, NULL) != 0)
				goto err;
		}
		/* L */
		if (action == ACTION_LIST) {
			PRINT_SCAN_LIST(*scan);
		}
		/* S */
		else if (action == ACTION_SCAN) {
			free_arp_scan(*scan);
			TELLRESCAN();
			if (!(*scan = nmapscan(arguments))) 
				goto err;
			if (fill_vendor_from_manuf_file(*scan) != 0)
				goto err;
		}
		else if (action == ACTION_CHANGE_PPM) {
			change_ppm(arguments);
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
		if (start_attack_some(arguments, scan, NULL) != 0)
			goto err;
	}
	else if (arguments->target_list != NULL) {
		ERROR_NO_TARGET_SUPPLIED();
	}
	else {
		WARNING_NETWORK_EMPTY();
	}
	return 0;
err:
	return 1;
}

static int spoofmode(nmap_r **scan, struct arguments *arguments)
{
	if (arguments->scanamount - 2 > 0) {
		printf("\n");
		if (arpspoof_some(arguments, scan, NULL) != 0)
			goto err;
	}
	else if (arguments->target_list != NULL) {
		ERROR_NO_TARGET_SUPPLIED();
	}
	else {
		WARNING_NETWORK_EMPTY();
	}
	return 0;
err:
	return 1;
}

static int restoremode(nmap_r **scan, struct arguments *arguments)
{
	if (arguments->scanamount - 2 > 0) {
		printf("\n");
		if (restore_some(arguments, scan, NULL) != 0)
			goto err;
	}
	else if (arguments->target_list != NULL) {
		ERROR_NO_TARGET_SUPPLIED();
	}
	else {
		WARNING_NETWORK_EMPTY();
	}
	return 0;
err:
	return 1;
}

int main(int argc, char **argv)
{
	struct arguments arguments = { 0x0 };
	nmap_r **scan = NULL; /* hold result of the arp nmap scan */

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

	ip_forward_status();

	TELLHEADER();

	if (arguments.mode == INTERACTIVE) {
		if (interactivemode(&scan, &arguments) != 0)
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
		if (arguments.target_list != NULL) {
			if (spoofmode(scan, &arguments) != 0)
				goto err;
		}
		else
			ERROR_NO_TARGET_SUPPLIED();
	}

	if (arguments.mode == RESTORE) {
		if (arguments.target_list != NULL) {
			if (restoremode(scan, &arguments) != 0)
				goto err;
		}
		else
			ERROR_NO_TARGET_SUPPLIED();
	}

	if (arguments.nmapflags != NULL)
		free(arguments.nmapflags);
	free_arp_scan(scan);
	TELLEXITING();
	return 0;

err:
	if (scan)
		free_arp_scan(scan);
	if (arguments.nmapflags != NULL)
		free(arguments.nmapflags);
	ERROR_EXIT();
	return 1;
}
