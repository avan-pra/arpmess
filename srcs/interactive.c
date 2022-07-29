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
		if (scan[i]->known_ha == 1) {
			printf("\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"%ld"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\t"MACCOLOR"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"ANSI_COLOR_RESET"\t"VENDORCOLOR"%s"ANSI_COLOR_RESET"\t"VENDORCOLOREXTRA"%s"ANSI_COLOR_RESET"\n",
			i,
			scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
			scan[i]->ha[0], scan[i]->ha[1], scan[i]->ha[2], scan[i]->ha[3], scan[i]->ha[4], scan[i]->ha[5],
			(scan[i]->vendor == NULL ? "N/A" : scan[i]->vendor),
			(scan[i]->vendor_extra == NULL ? "" : scan[i]->vendor_extra));
		}
		else { // probably useless
			printf("\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"%ld"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_RESET" "IPV4COLOR"%hhu.%hhu.%hhu.%hhu"ANSI_COLOR_RESET"\t"MACCOLOR"??:??:??:??:??:??"ANSI_COLOR_RESET"\t"VENDORCOLOR"%s"ANSI_COLOR_RESET"\t"VENDORCOLOREXTRA"%s"ANSI_COLOR_RESET"\n",
			i,
			scan[i]->pa[0], scan[i]->pa[1], scan[i]->pa[2], scan[i]->pa[3],
			"N/A",
			"");
		}
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

int ask_index_list(nmap_r **scan, const struct arguments *arguments, char **buf)
{
	size_t size = 0;
	char c;

	*buf = NULL;
	printf("\n%sChoose somes hosts from the list (comma separated if multiple):\n", SAMPLE_INFO);
	PRINT_SCAN_LIST(scan);
	printf("\n\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"R"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Return"ANSI_COLOR_RESET"\n\
\t"ANSI_COLOR_BRIGHT_YELLOW"["ANSI_COLOR_BRIGHT_RED"E"ANSI_COLOR_BRIGHT_YELLOW"]"ANSI_COLOR_BRIGHT_WHITE" Exit"ANSI_COLOR_RESET"\n\n"PROMPT);
	getline(buf, &size, stdin);
	if (*buf == NULL)
		{ ERROR_MALLOC(); return 1; }
	c = toupper(get_first_non_whitespace(*buf));
	if (c == 'E')
		return ACTION_EXIT;
	if (c == 'R')
		return ACTION_RETURN;
	return 0;
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
		|| action == '3' || action == '4'
		|| action == 'E' || action == 'S'
		||action == 'L')
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