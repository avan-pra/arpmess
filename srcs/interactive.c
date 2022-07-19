# include <stdio.h>
# include <stdlib.h>
# include <ctype.h>
# include "utils.h"

void PRINT_SCAN_LIST(nmap_r **scan)
{
	printf("\n");
	for (size_t i = 0; scan[i]; ++i) {
		if (scan[i]->gateway == 1) {
			printf(ANSI_COLOR_256_ORANGE"gateway"ANSI_COLOR_RESET);
		}
		if (scan[i]->self == 1) {
			printf(ANSI_COLOR_256_ORANGE"you"ANSI_COLOR_RESET);
		}
		printf("\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"%ld"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\t"MACCOLOR"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"ANSI_COLOR_RESET"\t"VENDORCOLOR"%s"ANSI_COLOR_RESET"\t"VENDORCOLOREXTRA"%s"ANSI_COLOR_RESET"\n",
		i,
		scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
		scan[i]->ha[0], scan[i]->ha[1], scan[i]->ha[2], scan[i]->ha[3], scan[i]->ha[4], scan[i]->ha[5],
		(scan[i]->vendor == NULL ? "N/A" : scan[i]->vendor),
		(scan[i]->vendor_extra == NULL ? "" : scan[i]->vendor_extra));
	}
}

char get_first_non_whitespace(char *buf)
{
	for (size_t i = 0; buf[i]; ++i) {
		if (!isspace(buf[i]))
			return buf[i];
	}
	return 0;
}

long long ask_index(nmap_r **scan, const struct arguments *arguments)
{
	long long target;
	char buffer[0x40];
	char c;

	printf("\n%sChoose an host from the list:\n", SAMPLE_INFO);
	PRINT_SCAN_LIST(scan);
	printf("\n\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"R"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Return"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"E"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Exit"ANSI_COLOR_RESET"\n\n"PROMPT);
	while (1) {
		fgets(buffer, 0x40, stdin);
		target = atoll(buffer);
		c = toupper(get_first_non_whitespace(buffer));
		if (c == 'E')
			return ACTION_EXIT;
		if (c == 'R')
			return ACTION_RETURN;
		if (((c >= '0' && c <= '9') || c == '+' || c == '-') && target >= 0 && target < arguments->scanamount && scan[target]->gateway == 0 && scan[target]->self == 0)
			break;
		if (((c >= '0' && c <= '9') || c == '+' || c == '-') && target >= 0 && target < arguments->scanamount && (scan[target]->gateway == 0 || scan[target]->self == 0))
			ERROR_CANT_SELECT_SELF_OR_GATEWAY();

		if (((c >= '0' && c <= '9') || c == '+' || c == '-'))
			ERROR_UNRECOGNIZED_LONG_ASK(target)
		else
			ERROR_UNRECOGNIZED_CHAR_ASK(c);
		printf("\n%sChoose an host from the list:\n\n", SAMPLE_INFO);
		PRINT_SCAN_LIST(scan);
		printf("\n\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"R"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Return"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"E"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Exit"ANSI_COLOR_RESET"\n\n"PROMPT);
	}
	return target;
}

/* attack one, refresh, etc... */
int ask_action()
{
	int action;
	char buffer[0x40];

	ASK_ATTACK_TYPE();
	while (1) {
		fgets(buffer, 0x40, stdin);
		action = toupper(buffer[0]);
		if (action == '1' || action == '2'
		|| action == '3' || action == 'E'
		|| action == 'S' || action == 'L')
			break;
		ERROR_UNRECOGNIZED_CHAR_ASK(action);
		ASK_ATTACK_TYPE();
	}
	if (action == 'E')
		return ACTION_EXIT;
	if (action == 'S')
		return ACTION_SCAN;
	if (action == 'L')
		return ACTION_LIST;
	return action;
}

int ask_user_for_gateway()
{
	return 0;
}