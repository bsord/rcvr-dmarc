FROM golang AS builder
WORKDIR /source
COPY . .
RUN make clean && make dependencies && make rcvrdmarcd
RUN mkdir /app && cp rcvrdmarcd /app/

FROM alpine

RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

WORKDIR /app

COPY --from=builder "/app" .

CMD ["/app/rcvrdmarcd", "serve"]