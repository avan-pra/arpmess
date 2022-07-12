FROM debian:bullseye

RUN apt update && apt install -y \
iputils-ping \
net-tools \
iproute2 \
curl

# for shared folder
RUN mkdir -p /root/arpmess

CMD ["tail", "-f", "/dev/null"]
