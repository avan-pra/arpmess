# include <stdio.h>
# include "utils.h"

static void PRINT_SCAN_LIST(nmap_r **scan, const struct arguments *arguments)
{
	printf("\n%sChoose an host from the list:\n\n", SAMPLE_INFO);
	for (size_t i = 0; scan[i]; ++i) {
		if (scan[i]->gateway == 1) {
			printf(ANSI_COLOR_BLUE"gateway"ANSI_COLOR_RESET);
		}
		if (scan[i]->self == 1) {
			printf(ANSI_COLOR_BLUE"you"ANSI_COLOR_RESET);
		}
		printf("\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"%d"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\t"MACCOLOR"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx"ANSI_COLOR_RESET"\t%s\t(%s)\n",
		i,
		scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
		scan[i]->ha[0], scan[i]->ha[1], scan[i]->ha[2], scan[i]->ha[3], scan[i]->ha[4], scan[i]->ha[5],
		scan[i]->vendor,
		scan[i]->vendor_extra);
	}
	printf("\n\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"E"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Exit"ANSI_COLOR_RESET"\n\n"PROMPT);
}

int ask_index(nmap_r **scan, const struct arguments *arguments)
{
	unsigned int target;
	char c;

	PRINT_SCAN_LIST(scan, arguments);
	while (1) {
		scanf(" %u", &target);
		if (target < arguments->scanamount && scan[target]->gateway == 0 && scan[target]->self == 0)
			break;
		c = getchar();
		if (c == 'E')
			return -1;
		if (target < arguments->scanamount && (scan[target]->gateway == 0 || scan[target]->self == 0))
			ERROR_CANT_SELECT_SELF_OR_GATEWAY();
		ERROR_UNRECOGNIZED_UINTEGER_ASK(target);
		PRINT_SCAN_LIST(scan, arguments);
	}
	return target;
}

int ask_attack_type()
{
	int action;

	ASK_ATTACK_TYPE();
	while (1) {
		scanf(" %c", &action);
		if (action == '1' || action == '2'
		|| action == '3' || action == 'E')
			break;
		ERROR_UNRECOGNIZED_CHAR_ASK(action);
		ASK_ATTACK_TYPE();
	}
	return action;
}

int ask_user_for_gateway()
{
	;
}