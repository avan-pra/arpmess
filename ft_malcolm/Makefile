NAME = ft_malcolm

CC = gcc

CFLAGS = -Wall -Wextra -Werror -I$(HEAD_DIR)

HEAD_DIR = ./head/

SRCS = $(addprefix $(DIR_SRCS), $(SRCSFILE))
DIR_SRCS = ./srcs/
SRCSFILE = \
	main.c \
	argparse.c \
	utils.c \
	arpspoof.c

OBJ = $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) -o $(NAME)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean $(NAME)
