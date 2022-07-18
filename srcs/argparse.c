#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "struct.h"
#include "define.h"

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
*/
static struct argp_option options[] =
{
	{ "interface", 'i', "INTERFACE_NAME", 0, "Specify interface to use (ex: eth0) IF_NAMESIZE max" },
	{ "packets", 'p', "NUMBER", 0, "Number of packets broadcasted per minute (default: 12)" },
	{ "target", 't', "IP1,IP2", 0, "Target list YET TO BE IMPLEMENTED"},
	{ "verbose", 'v', 0, 0, "Produce verbose output USELESS AS OF NOW" },
	{0x0}
};

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

		case 'p':
			arguments->ppm = atoi(arg);
			if (arguments->ppm <= 0) {
				printf("%sAmount of packets sent per minute must be > 0, currently: %d\n", SAMPLE_ERROR, arguments->ppm);
				argp_usage(state);
			}

		case 't':
			arguments->target_list = arg;
			break;

		case ARGP_KEY_ARG:
			argp_usage(state);
			break;

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
"arpmess -- A kickthemout like rewrite in C\
\v\
"IFACECOLOR"Color for interface\n\
"IPV4COLOR"Color for ipv4\n\
"MACCOLOR"Color for mac addresses\n\
"NETMASKCOLOR"Color for netmask\
"ANSI_COLOR_RESET;

	static struct argp argp = { options, parse_opt, args_doc, doc };

	return argp_parse(&argp, argc, argv, 0, 0, arguments);
}