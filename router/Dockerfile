FROM alpine:3.20

RUN apk add --no-cache squid

# Create required dirs for read-only rootfs + tmpfs mounts (compose)
RUN mkdir -p /var/cache/squid /var/log/squid && \
    chown -R squid:squid /var/cache/squid /var/log/squid

USER squid

EXPOSE 3128

CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]


