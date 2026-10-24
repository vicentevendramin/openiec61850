# The openiec61850 interop runner (interop/runner). Build context: the repository root.
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
COPY interop/runner interop/runner
RUN cmake -S interop/runner -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build \
 && cmake --install /build --prefix /opt/openiec61850

FROM ubuntu:24.04
COPY --from=build /opt/openiec61850/bin/openiec61850_interop /usr/local/bin/
ENTRYPOINT ["openiec61850_interop"]
