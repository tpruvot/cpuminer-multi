FROM alpine:latest

RUN apk add --no-cache \
    libcurl \
    libgcc \
    libstdc++ \
    openssl \
    autoconf \
    automake \
    build-base \
    curl \
    curl-dev \
    git \
    openssl-dev
RUN git clone https://github.com/tpruvot/cpuminer-multi
WORKDIR cpuminer-multi 
RUN ./autogen.sh
RUN ./configure CFLAGS="-O3 -march=native" --with-crypto --with-curl
RUN make install
RUN apk del --purge \
    libcurl \
    libgcc \
    libstdc++ \
    autoconf \
    automake \
    build-base \
    git
RUN ./cpuminer --help
ENTRYPOINT [ "./cpuminer" ]
