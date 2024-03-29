# Build Geth in a stock Go builder container
FROM golang:1.13-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git

ADD . /Elastos.ELA.SideChain.EID
RUN cd /Elastos.ELA.SideChain.EID && make geth bootnode

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /Elastos.ELA.SideChain.EID/build/bin/* /usr/local/bin/

EXPOSE 20646 20645 20647 20648 20648/udp
#ENTRYPOINT ["geth"]
