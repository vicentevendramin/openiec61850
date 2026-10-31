# The IEC61850bean console server and console client as interoperability peers (ADR 0007). Build
# context: the repository root.
#
# Clean-room rule (ADR 0001): this image only downloads the released binary jars, pinned by SHA-256
# in fetch.sh, and runs them. Nobody working on openiec61850 reads, copies or inspects the
# IEC61850bean sources, and no sources jar is fetched.
FROM ubuntu:24.04 AS fetch

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY interop/iec61850bean/fetch.sh /usr/local/bin/fetch.sh
RUN bash /usr/local/bin/fetch.sh /opt/iec61850bean

FROM eclipse-temurin:21.0.13_9-jre-noble@sha256:03fedab2c0d7355868b5ba5330d64088b956a0bfac48f904e5c57207e261e2c9
COPY --from=fetch /opt/iec61850bean /opt/iec61850bean
COPY interop/iec61850bean/server.sh interop/iec61850bean/run_client.sh /usr/local/bin/
COPY interop/server/simpleIO.icd /etc/openiec61850/simpleIO.icd
RUN chmod +x /usr/local/bin/server.sh /usr/local/bin/run_client.sh
ENV BEAN_LIB=/opt/iec61850bean
EXPOSE 102
# Ready once the TCP port accepts connections.
HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/102"]
CMD ["server.sh", "/etc/openiec61850/simpleIO.icd", "102"]
