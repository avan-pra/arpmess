#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "struct.h"
#include "define.h"
#include "utils.h"

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
*/
static struct argp_option options[] =
{
	{ "mode", 'm', "INTERACTIVE/KICK/SPOOF", 0, "Defaults to INTERACTIVE, if KICK/SPOOF is selected, -t arguments MUST be specified,       ex: `-m KICK`", 0x0},
	{ "interface", 'i', "INTERFACE_NAME", 0, "Specify interface to use ex: `-i eth0` (IF_NAMESIZE max)", 0x0 },
	{ "packets", 'p', "PACKETPERMINUTE", 0, "Number of packets broadcasted per minute ex: `-p 24` (default: 12) WARNING: 0 for unlimited, very resource intensive", 0x0 },
	{ "netmask", 'n', "CIDR", 0, "Use netmask to look for hosts instead of the network one IN CIDR NOTATION ex: `-n 24` for 255.255.255.0", 0x0 },
	{ "nmapflag", 'f', "-FLAG1 -FLAG2", 0, "Add flag to nmap command \nWARNING: don't play with this option unless you know what you are doing", 0x0},
	{ "target", 't', "IP1,IP2", 0, "Target list (comma separated), only found target will be used by the program                     ex: `-t 192.168.43.10,192.168.43.152`", 0x0 },
	{ "verbose", 'v', 0, 0, "Produce verbose output USELESS AS OF NOW", 0x0 },
	{0x0}
};

/*
** -f flag may be used to run arbitrary command, disable by setting
** arguments->nmapflags to NULL in case 'f'
*/

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key)
	{
		case 'v':
			arguments->verbose = 1;
			break;

		case 'i':
			strncpy(arguments->ifacename, arg, sizeof(arguments->ifacename));
			break;

		case 'n': {
			*(uint32_t*)arguments->netmask = ntohl(~(0xFFFFFFFF >> atoi(arg)));
			arguments->sys_netmask = 0;
			break;
		}

		case 'f': {
			if (!(arguments->nmapflags = strdup(arg))) {
				ERROR_MALLOC();
				return ARGP_ERR_UNKNOWN;
			}
			break;
		}

		case 'm': {
			char *str;
			if (!(str = strdup(arg)))
				{ ERROR_MALLOC(); return ARGP_ERR_UNKNOWN; }
			to_upper_str(str);
			if (strncmp(str, "INTERACTIVE", 11) == 0)
				arguments->mode = INTERACTIVE;
			else if (strncmp(str, "KICK", 4) == 0)
				arguments->mode = KICK;
			else if (strncmp(str, "SPOOF", 5) == 0)
				arguments->mode = SPOOF;
			else {
				ERROR_UNKNOWN_MODE(arg);
				free(str);
				argp_usage(state);
			}
			free(str);
			break;
		}

		case 'p': {
			arguments->ppm = atoi(arg);
			if (arguments->ppm < 0) {
				ERROR_PACKET_PER_MINUTE();
				argp_usage(state);
			}
			break;
		}
		case 't':
			arguments->target_list = arg;
			break;

		case ARGP_KEY_ARG: {
			argp_usage(state);
			break;
		}

		case ARGP_KEY_END:
			break;

		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int argparse(int argc, char **argv, struct arguments *arguments)
{
static char args_doc[] = "";
static char doc[] = \
"arpmess -- An arpspoofing software, all in one in C\
\v\
"IFACECOLOR"Color for interface\n\
"IPV4COLOR"Color for ipv4\n\
"MACCOLOR"Color for mac addresses\n\
"NETMASKCOLOR"Color for netmask\
"ANSI_COLOR_RESET;

	static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

	return argp_parse(&argp, argc, argv, 0, 0, arguments);
}