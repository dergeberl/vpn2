# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

GARDENER_HACK_DIR    		  := $(shell go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
VERSION                       := $(shell cat VERSION)
REPO_ROOT                     := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
REGISTRY                      := europe-docker.pkg.dev/gardener-project/public/gardener
PREFIX                        := vpn
SEED_SERVER_IMAGE_REPOSITORY  := $(REGISTRY)/$(PREFIX)-seed-server
SEED_SERVER_IMAGE_TAG         := $(VERSION)
SHOOT_CLIENT_IMAGE_REPOSITORY := $(REGISTRY)/$(PREFIX)-shoot-client
SHOOT_CLIENT_IMAGE_TAG        := $(VERSION)
LD_FLAGS                      := "-w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION "vpn2")"

IMAGE_TAG             := $(VERSION)
EFFECTIVE_VERSION     := $(VERSION)-$(shell git rev-parse HEAD)
ARCH                := amd64

PATH                          := $(GOBIN):$(PATH)

export PATH

.PHONY: tidy
tidy:
	@GO111MODULE=on go mod tidy

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

.PHONY: check
check:
	go fmt ./...
	go vet ./...

.PHONY: test
test:
	go test ./...

.PHONY: build
build: build-acquire-ip build-openvpn-exporter build-seed-server build-shoot-client

.PHONY: build-acquire-ip
build-acquire-ip:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) GO111MODULE=on go build -o bin/acquire-ip \
	    -ldflags $(LD_FLAGS)\
	    ./cmd/acquire_ip/main.go

.PHONY: build-openvpn-exporter
build-openvpn-exporter:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) GO111MODULE=on go build -o bin/openvpn-exporter  \
	    -ldflags $(LD_FLAGS)\
	    ./cmd/openvpn_exporter/main.go

.PHONY: build-seed-server
build-seed-server:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/seed-server  \
	    -ldflags $(LD_FLAGS)\
	    ./cmd/seed_server/main.go

.PHONY: build-shoot-client
build-shoot-client:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/shoot-client  \
	    -ldflags $(LD_FLAGS)\
	    ./cmd/shoot_client/main.go
