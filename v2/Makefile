APP_NAME ?= oneshot
IMAGE_REGISTRY ?= docker.io/raphaelreyna
GIT_REPO ?= github.com/forestnode-io/oneshot/v2

VERSION=`git describe --tags --abbrev=0`
VERSION_FLAG=$(GIT_REPO)/pkg/version.Version=$(VERSION)
API_VERSION=v1.0.0
API_VERSION_FLAG=$(GIT_REPO)/pkg/version.APIVersion=$(API_VERSION)
STATIC_FLAG=-extldflags=-static
GOBIN=$(shell go env GOPATH)/bin

BUILD_OUTPUT_DIR=./build-output
APP_LOCATION=$(BUILD_OUTPUT_DIR)/$(APP_NAME)
WEBRTC_CLIENT_DIR=./browser/webrtc-client
UPLOAD_CLIENT_DIR=./browser/upload-client

$(APP_NAME): webrtc-client upload-client
	mkdir -p ./build-output
	go build -o $(APP_LOCATION) \
		-trimpath \
		-ldflags "${STATIC_FLAG} -X ${VERSION_FLAG} -X ${API_VERSION_FLAG} -s -w" \
		./cmd/...

compressed: $(APP_NAME)
	upx --best --brute --no-lzma $(APP_LOCATION)

$(APP_NAME).1:
	go run -ldflags "-X ${VERSION_FLAG}" \
	       	./build-tools/man/main.go > $(APP_LOCATION).1

install-man-page: $(APP_NAME).1
	mv $(APP_LOCATION).1 $(MANPATH)/man1
	mandb

.PHONY: image
image:
	docker build -t $(IMAGE_REGISTRY)/$(APP_NAME):$(VERSION) .

.PHONY: itest
itest: $(APP_NAME)
	go test -count 1 -p 1 -timeout 30s ./integration_testing/...

.PHONY: itest-full
itest-without-internet: $(APP_NAME)
	go test -without-internet -count 1 -p 1 -timeout 30s ./integration_testing/...

.PHONY: lint
lint:
	$(GOBIN)/golangci-lint run

dep:
	go mod download

vet:
	go vet ./...

.PHONY: webrtc-client
webrtc-client:
	npm --prefix $(WEBRTC_CLIENT_DIR) i && npm --prefix $(WEBRTC_CLIENT_DIR) run build
	cp $(WEBRTC_CLIENT_DIR)/dist/main.minified.js ./pkg/commands/discovery-server/template/webrtc-client.js
	cp $(WEBRTC_CLIENT_DIR)/dist/sd-streams-polyfill.min.js ./pkg/commands/discovery-server/template/sd-streams-polyfill.min.js

.PHONY: upload-client
upload-client:
	npm --prefix $(UPLOAD_CLIENT_DIR) i && npm --prefix $(UPLOAD_CLIENT_DIR) run build
	cp $(UPLOAD_CLIENT_DIR)/dist/main.minified.js ./pkg/commands/receive/main.js

clean:
	rm -rf $(BUILD_OUTPUT_DIR)
	rm -rf $(WEBRTC_CLIENT_DIR)/node_modules
	rm -rf $(WEBRTC_CLIENT_DIR)/dist
	rm -rf $(UPLOAD_CLIENT_DIR)/node_modules
	rm -rf $(UPLOAD_CLIENT_DIR)/dist
	rm ./pkg/commands/discovery-server/template/webrtc-client.js
	rm ./pkg/commands/discovery-server/template/sd-streams-polyfill.min.js