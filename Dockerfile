FROM alpine:3
ARG TZ=UTC
RUN apk add --no-cache bash bash-completion bind-tools go make qemu-img qemu-system-x86_64 tzdata
RUN ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
WORKDIR /work
CMD ["bash", "-l"]
