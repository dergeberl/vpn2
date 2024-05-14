# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# gobuilder
FROM golang:1.22.3 AS gobuilder

WORKDIR /build
COPY ./VERSION ./VERSION
COPY ./.git ./.git
COPY ./Makefile ./Makefile
COPY ./go.mod /go.sum ./
RUN go mod download
COPY ./cmd ./cmd
COPY ./pkg ./pkg
ARG TARGETARCH
RUN make build-openvpn-exporter build-seed-server GOARCH=$TARGETARCH

FROM cgr.dev/chainguard/wolfi-base
RUN apk add openvpn ip6tables iptables
# delete apk to ensure no additional packages can be installed
RUN rm $(which apk)
RUN rm -r /var/cache/apk
COPY --from=gobuilder /build/bin/openvpn-exporter /build/bin/seed-server /bin/
ENTRYPOINT [ "/bin/seed-server" ]
