# The libiec61850 example clients plus run_clients.sh (reverse interop: libiec61850 clients against
# openiec61850-server). Built on the libiec61850 image, so interop/run.sh builds that one first.
ARG LIBIEC61850_VERSION=1.6.0
FROM openiec61850-interop/libiec61850:${LIBIEC61850_VERSION}
COPY run_clients.sh /usr/local/bin/run_clients.sh
RUN chmod +x /usr/local/bin/run_clients.sh
HEALTHCHECK NONE
ENTRYPOINT ["run_clients.sh"]
