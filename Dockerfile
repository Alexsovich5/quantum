FROM python:3.8.3-buster@sha256:0919808810c11f09713ac50bd0c428f34a34029028f0b535020165659e39ec6a

RUN printf '%s\n' \
      'deb https://snapshot.debian.org/archive/debian/20200615T000000Z buster main' \
      'deb https://snapshot.debian.org/archive/debian-security/20200615T000000Z buster/updates main' \
      > /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot

RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build \
 && rm -rf /var/lib/apt/lists/*

ARG LIBOQS_COMMIT=f6ca3dca5e95e77267dd0d7f5480c512cd6a4d6d
ARG LIBOQS_SHA256=bae2ec508c9a7c8d25ab873c91cc31682536209a1a324d56afae5a5e6bcf11c6
RUN cd /tmp \
 && curl -fsSL --retry 3 -o liboqs.tar.gz \
      https://github.com/open-quantum-safe/liboqs/archive/${LIBOQS_COMMIT}.tar.gz \
 && echo "${LIBOQS_SHA256}  liboqs.tar.gz" | sha256sum -c - \
 && tar xzf liboqs.tar.gz \
 && cmake -S liboqs-${LIBOQS_COMMIT} -B liboqs-build -GNinja \
      -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/usr/local \
 && ninja -C liboqs-build install \
 && ldconfig \
 && rm -rf /tmp/liboqs*

WORKDIR /app

COPY requirements-build.txt requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-build.txt \
 && pip install --no-cache-dir --no-build-isolation --no-binary cryptography \
      -r requirements.txt -r requirements-dev.txt

ARG LIBOQS_PYTHON_COMMIT=97e500c7eb74ec8acd14910b4d4a7e7b65dbeb5b
ARG LIBOQS_PYTHON_SHA256=6a31d0aad459bad134840cff45fa7b08e12b918f20dbce0555ee889c5957ada6
RUN cd /tmp \
 && curl -fsSL --retry 3 -o liboqs-python.tar.gz \
      https://github.com/open-quantum-safe/liboqs-python/archive/${LIBOQS_PYTHON_COMMIT}.tar.gz \
 && echo "${LIBOQS_PYTHON_SHA256}  liboqs-python.tar.gz" | sha256sum -c - \
 && tar xzf liboqs-python.tar.gz \
 && pip install --no-cache-dir --no-build-isolation ./liboqs-python-${LIBOQS_PYTHON_COMMIT} \
 && rm -rf /tmp/liboqs-python*

ENV PYTHONPATH=/app/src
