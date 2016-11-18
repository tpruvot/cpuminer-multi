FROM ubuntu:xenial
MAINTAINER alexellis2@gmail.com

WORKDIR /root/

RUN apt-get update && apt-get -qy install \
 automake \
 build-essential \
 libcurl4-openssl-dev \
 libssl-dev \
 git

RUN git clone --recursive https://github.com/tpruvot/cpuminer-multi.git
WORKDIR /root/cpuminer-multi

RUN git checkout linux


RUN ./autogen.sh
RUN ./configure CFLAGS="-O3" --with-crypto --with-curl
RUN make

ENTRYPOINT	["./cpuminer"]
