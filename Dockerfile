FROM --platform=${BUILDPLATFORM} golang:alpine as builder

RUN apk add --no-cache make git ca-certificates && \
    wget -O /Country.mmdb https://raw.githubusercontent.com/yaling888/geoip/release/Country.mmdb && \
    wget -O /geosite.dat https://raw.githubusercontent.com/yaling888/geosite/release/geosite.dat
WORKDIR /workdir
COPY --from=tonistiigi/xx:golang / /
ARG TARGETOS TARGETARCH TARGETVARIANT

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    make BINDIR= ${TARGETOS}-${TARGETARCH}${TARGETVARIANT} && \
    mv /clash* /clash

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/yaling888/clash"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /Country.mmdb /root/.config/clash/
COPY --from=builder /geosite.dat /root/.config/clash/
COPY --from=builder /clash /
ENTRYPOINT ["/clash"]
