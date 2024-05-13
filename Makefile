# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

VERSION                       := $(shell cat VERSION)
REGISTRY                      := europe-docker.pkg.dev/gardener-project/public/gardener
PREFIX                        := vpn
SEED_SERVER_IMAGE_REPOSITORY  := $(REGISTRY)/$(PREFIX)-seed-server
SEED_SERVER_IMAGE_TAG         := $(VERSION)
SHOOT_CLIENT_IMAGE_REPOSITORY := $(REGISTRY)/$(PREFIX)-shoot-client
SHOOT_CLIENT_IMAGE_TAG        := $(VERSION)

IMAGE_TAG             := $(VERSION)
EFFECTIVE_VERSION     := $(VERSION)-$(shell git rev-parse HEAD)
GOARCH                := amd64

PATH                          := $(GOBIN):$(PATH)

export PATH

.PHONY: seed-server-docker-image
seed-server-docker-image:
	@docker build -t $(SEED_SERVER_IMAGE_REPOSITORY):$(SEED_SERVER_IMAGE_TAG) -f seed-server/Dockerfile --rm .

.PHONY: shoot-client-docker-image
shoot-client-docker-image:
	@docker build -t $(SHOOT_CLIENT_IMAGE_REPOSITORY):$(SHOOT_CLIENT_IMAGE_TAG) -f shoot-client/Dockerfile --rm .

.PHONY: docker-images
docker-images: seed-server-docker-image shoot-client-docker-image

.PHONY: release
release: docker-images docker-login docker-push

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-push
docker-push:
	@if ! docker images $(SEED_SERVER_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(SEED_SERVER_IMAGE_TAG); then echo "$(SEED_SERVER_IMAGE_REPOSITORY) version $(SEED_SERVER_IMAGE_TAG) is not yet built. Please run 'make seed-server-docker-image'"; false; fi
	@if ! docker images $(SHOOT_CLIENT_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(SHOOT_CLIENT_IMAGE_TAG); then echo "$(SHOOT_CLIENT_IMAGE_REPOSITORY) version $(SHOOT_CLIENT_IMAGE_TAG) is not yet built. Please run 'make shoot-client-docker-image'"; false; fi
	@gcloud docker -- push $(SEED_SERVER_IMAGE_REPOSITORY):$(SEED_SERVER_IMAGE_TAG)
	@gcloud docker -- push $(SHOOT_CLIENT_IMAGE_REPOSITORY):$(SHOOT_CLIENT_IMAGE_TAG)

#.PHONY: revendor
#revendor:
#	@GO111MODULE=on go mod vendor
#	@GO111MODULE=on go mod tidy

.PHONY: check
check:
	go fmt ./...
	go vet ./...

.PHONY: test
test:
	go test ./...

.PHONY: build
build: build-acquire-ip build-openvpn-exporter

.PHONY: build-acquire-ip
build-acquire-ip:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GO111MODULE=on go build -o acquire-ip \
	    -ldflags "-X 'main.Version=$(EFFECTIVE_VERSION)' -X 'main.ImageTag=$(IMAGE_TAG)'"\
	    ./cmd/acquire_ip/main.go

.PHONY: build-openvpn-exporter
build-openvpn-exporter:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GO111MODULE=on go build -o openvpn-exporter  \
	    -ldflags "-X 'main.Version=$(EFFECTIVE_VERSION)' -X 'main.ImageTag=$(IMAGE_TAG)'"\
	    ./cmd/openvpn_exporter/main.go

