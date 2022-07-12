
all:


container:
				docker build -t arpmessimg .
				docker run --name workctn -dit --cap-add=NET_ADMIN -v $(shell pwd):/root/arpmess arpmessimg
				docker run --name victctn -dit arpmessimg

shell:
				docker exec -ti -w /root/arpmess workctn /bin/bash

v_shell:
				docker exec -ti victctn /bin/bash

arp_v:
				docker exec -ti victctn /usr/sbin/ip n

delete:
				docker rm -f workctn victctn
