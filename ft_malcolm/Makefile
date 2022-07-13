NAME = ft_malcolm

CC = gcc

CFLAGS =

SRCS = $(addprefix $(DIR_SRCS), $(SRCSFILE))
DIR_SRCS = ./srcs/
SRCSFILE = \
	main.c

OBJ = $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) -o $(NAME)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean $(NAME)
