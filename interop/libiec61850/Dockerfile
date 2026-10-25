# libiec61850 example servers and clients as interoperability peers (ADR 0007).
#
# Clean-room rule (ADR 0001): this image only downloads a libiec61850 release, runs its own build
# system and keeps the resulting example executables. Nobody working on openiec61850 reads, copies
# or inspects the libiec61850 sources; only the binaries are executed.
FROM ubuntu:24.04 AS build

ARG LIBIEC61850_VERSION=1.6.0
# Optional: pin the release tarball (sha256). Empty skips the check.
ARG LIBIEC61850_SHA256=""
# Example servers (interop runner peers) and example clients (reverse interop against the
# openiec61850-server tool) kept in the image; the build fails if one is missing.
ARG EXAMPLES="server_example_basic_io server_example_control \
  iec61850_client_example1 iec61850_client_example2 iec61850_client_example4 \
  iec61850_client_example_reporting iec61850_client_example_rcbAsync iec61850_client_async \
  client_example_control mms_utility"

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      build-essential cmake ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
RUN curl -fsSL -o libiec61850.tar.gz \
      "https://github.com/mz-automation/libiec61850/archive/refs/tags/v${LIBIEC61850_VERSION}.tar.gz" \
 && if [ -n "${LIBIEC61850_SHA256}" ]; then \
      echo "${LIBIEC61850_SHA256}  libiec61850.tar.gz" | sha256sum -c -; fi \
 && mkdir src && tar -xzf libiec61850.tar.gz -C src --strip-components=1 \
 && cmake -S src -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=ON > /dev/null \
 && cmake --build build --parallel "$(nproc)" > /dev/null \
 && mkdir -p /opt/libiec61850/bin /opt/libiec61850/lib \
 && for name in ${EXAMPLES}; do \
      exe="$(find build -type f -perm -u+x -name "${name}" | head -n 1)"; \
      if [ -z "${exe}" ]; then echo "example ${name} was not built" >&2; exit 1; fi; \
      cp "${exe}" /opt/libiec61850/bin/; \
    done \
 && find build -name 'lib*.so*' -exec cp -P {} /opt/libiec61850/lib/ \;

FROM ubuntu:24.04
COPY --from=build /opt/libiec61850 /opt/libiec61850
ENV PATH=/opt/libiec61850/bin:${PATH} \
    LD_LIBRARY_PATH=/opt/libiec61850/lib
# MMS over ISO/TCP (RFC 1006) on the well-known port; the examples listen on it by default.
EXPOSE 102
# Ready once the TCP port accepts connections.
HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/102"]
CMD ["server_example_basic_io"]
