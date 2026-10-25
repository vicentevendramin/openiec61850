# The libiec61850 example clients plus run_clients.sh (reverse interop: libiec61850 clients against
# openiec61850-server). Built by compose.yaml, which provides the libiec61850 image as the
# "libiec61850" build context (additional_contexts: service:basic-io).
FROM libiec61850
COPY run_clients.sh /usr/local/bin/run_clients.sh
RUN chmod +x /usr/local/bin/run_clients.sh
HEALTHCHECK NONE
ENTRYPOINT ["run_clients.sh"]
