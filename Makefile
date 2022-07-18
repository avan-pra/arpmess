NAME = arpmess

CC = gcc

CFLAGS = -I$(HEAD_DIR) -lpthread -lm

HEAD_DIR = ./head/

SRCS = $(addprefix $(DIR_SRCS), $(SRCSFILE))
DIR_SRCS = ./srcs/
SRCSFILE = \
	main.c \
	argparse.c \
	interactive.c \
	network.c \
	utils.c \
	attack.c

OBJ = $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) -o $(NAME)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean $(NAME)

vendor:
	curl https://gitlab.com/wireshark/wireshark/-/raw/master/manuf --output manuf || wget https://gitlab.com/wireshark/wireshark/-/raw/master/manuf

copy:
	docker cp arpmess workctn:/root/arpmess

container:
	docker build -t arpmessimg .
	docker run --name workctn -dit --cap-add=NET_ADMIN --cap-add=NET_RAW arpmessimg
	docker run --name victctn -dit --cap-add=NET_ADMIN arpmessimg

start:
	docker start workctn victctn

delete:
	docker rm -f workctn victctn

shell:
	docker exec -ti -w /root/arpmess workctn /bin/bash

v_shell:
	docker exec -ti victctn /bin/bash
