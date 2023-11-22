FROM alpine:3.18.4 as build-stage

RUN apk add --no-cache \
  build-base=0.5-r3 \
  openssl-dev=3.1.4-r1 \
  libqrencode-dev=4.1.1-r1

WORKDIR /src

COPY bitcoin-keygen.c /src/bitcoin-keygen.c
COPY Makefile /src/Makefile

RUN make

FROM alpine:3.18.4 as execution-stage

RUN apk add --no-cache libqrencode=4.1.1-r1

COPY --from=build-stage /src/bitcoin-keygen /usr/bin/bitcoin-keygen

RUN addgroup bitcoin && adduser -S bitcoin -G bitcoin

WORKDIR /home/bitcoin

USER bitcoin

ENV HOME /home/bitcoin

# Set an environment variable to make it run non-interactively
ENV RANDFILE=/root/.rnd

CMD ["bitcoin-keygen"]