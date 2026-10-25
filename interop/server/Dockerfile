# The openiec61850-server tool serving interop/server/simpleIO.icd, the peer of the libiec61850
# example clients (interop/clients). Build context: the repository root.
FROM ubuntu:24.04 AS build

ARG VCPKG_COMMIT=a073c28e52d920cb2465a17512324b3b6684d03a

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      build-essential cmake ninja-build git curl zip unzip tar pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone -q https://github.com/microsoft/vcpkg.git /opt/vcpkg \
 && git -C /opt/vcpkg checkout -q "${VCPKG_COMMIT}" \
 && /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics
ENV VCPKG_ROOT=/opt/vcpkg

WORKDIR /src
COPY vcpkg.json CMakeLists.txt ./
COPY cmake cmake
COPY include include
COPY src src
COPY tools tools
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENIEC61850_BUILD_TESTS=OFF \
      -DOPENIEC61850_BUILD_TOOLS=ON \
 && cmake --build /build --target openiec61850_server_tool openiec61850_client_tool \
 && mkdir -p /opt/openiec61850/bin \
 && cp /build/tools/openiec61850-server /build/tools/openiec61850-client /opt/openiec61850/bin/

FROM ubuntu:24.04
COPY --from=build /opt/openiec61850/bin/ /usr/local/bin/
COPY interop/server/simpleIO.icd /etc/openiec61850/simpleIO.icd
EXPOSE 102
HEALTHCHECK --interval=2s --timeout=2s --retries=30 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/102"]
ENTRYPOINT ["openiec61850-server", "--scl", "/etc/openiec61850/simpleIO.icd"]
CMD ["--simulate", "--verbose"]
