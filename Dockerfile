FROM python:3.8.3-buster@sha256:0919808810c11f09713ac50bd0c428f34a34029028f0b535020165659e39ec6a

RUN printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20200615T000000Z buster main' \
      'deb http://snapshot.debian.org/archive/debian-security/20200615T000000Z buster/updates main' \
      > /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot

WORKDIR /app

COPY requirements-build.txt requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-build.txt \
 && pip install --no-cache-dir --no-build-isolation --no-binary cryptography \
      -r requirements.txt -r requirements-dev.txt

ENV PYTHONPATH=/app/src
