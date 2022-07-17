# include <stdio.h>
# include "utils.h"

int ask_attack_type()
{
	int action;

	ASK_ATTACK_TYPE();
	while (scanf(" %c", &action) == 0)
		ASK_ATTACK_TYPE();
}

int ask_user_for_gateway()
{
	;
}