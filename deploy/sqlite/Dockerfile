# kbox pod image for the sqllogictest corpus.
#
# The pod runs unprivileged: namespaces, overlay rootfs, and networking all
# happen inside the in-process LKL kernel. The image carries the daemon, the
# Docker Engine shim, and the driver that walks the corpus.
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY kbox /usr/local/bin/kbox
COPY kbox-dockerd.py /usr/local/bin/kbox-dockerd.py
COPY slt-pod-driver.py /usr/local/bin/slt-pod-driver.py
RUN chmod 0755 /usr/local/bin/kbox /usr/local/bin/kbox-dockerd.py \
    /usr/local/bin/slt-pod-driver.py

EXPOSE 2376

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec /usr/local/bin/kbox daemon --sock /run/kbox/kboxd.sock --config /etc/kbox/kbox-config.yaml -v"]
