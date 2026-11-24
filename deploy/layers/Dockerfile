# kbox pod image: the kbox daemon plus its Docker Engine shim.
#
# Nothing here needs privileges. Namespaces, overlay rootfs, and networking are
# built inside the in-process LKL kernel, so the pod runs unprivileged.
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY kbox /usr/local/bin/kbox
COPY kbox-dockerd.py /usr/local/bin/kbox-dockerd.py
RUN chmod 0755 /usr/local/bin/kbox /usr/local/bin/kbox-dockerd.py

EXPOSE 2376

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec /usr/local/bin/kbox daemon --sock /run/kbox/kboxd.sock --config /etc/kbox/kbox-config.yaml -v"]
