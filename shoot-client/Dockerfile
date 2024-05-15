# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# gobuilder
FROM --platform=$BUILDPLATFORM golang:1.22.3 AS gobuilder

WORKDIR /build
COPY ./VERSION ./VERSION
COPY ./go.mod /go.sum ./
RUN go mod download
COPY ./.git ./.git
COPY ./cmd ./cmd
COPY ./pkg ./pkg
COPY ./Makefile ./Makefile
ARG TARGETARCH
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" make build-shoot-client GOARCH=$TARGETARCH

FROM --platform=$TARGETPLATFORM cgr.dev/chainguard/wolfi-base
RUN apk update && \
    apk add openvpn ip6tables iptables && \
    rm $(which apk) && \
    rm -r /var/cache/apk
COPY --from=gobuilder /build/bin/shoot-client /bin/shoot-client
ENTRYPOINT [ "/bin/shoot-client" ]
