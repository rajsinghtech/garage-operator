# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Local Development

KIND_CLUSTER_DEV ?= garage-operator-dev
KIND_CONFIG ?= hack/kind-config.yaml
IMG_DEV ?= garage-operator:dev

.PHONY: dev-up
dev-up: ## Set up local development environment with kind cluster and operator
	@chmod +x hack/setup-dev.sh
	@hack/setup-dev.sh

.PHONY: dev-reset
dev-reset: ## Reset local development environment (delete and recreate cluster)
	@chmod +x hack/setup-dev.sh
	@hack/setup-dev.sh --reset

.PHONY: dev-down
dev-down: ## Tear down local development environment
	@kind delete cluster --name $(KIND_CLUSTER_DEV) 2>/dev/null || true
	@echo "Development cluster deleted"

.PHONY: dev-load
dev-load: docker-build ## Rebuild and reload operator image into kind cluster
	@docker tag ${IMG} $(IMG_DEV)
	@kind load docker-image $(IMG_DEV) --name $(KIND_CLUSTER_DEV)
	@kubectl rollout restart deployment/garage-operator-controller-manager -n garage-operator-system
	@echo "Operator image reloaded. Waiting for rollout..."
	@kubectl rollout status deployment/garage-operator-controller-manager -n garage-operator-system --timeout=60s

.PHONY: dev-logs
dev-logs: ## Stream operator logs
	@kubectl logs -f deployment/garage-operator-controller-manager -n garage-operator-system -c manager

.PHONY: dev-test
dev-test: ## Apply test resources to development cluster
	@kubectl apply -f hack/test-resources.yaml
	@echo "Test resources applied. Check status with:"
	@echo "  kubectl get garageclusters,garagebuckets,garagekeys -n garage-system"

.PHONY: dev-status
dev-status: ## Show status of all garage resources
	@echo "=== GarageClusters ===" && kubectl get garageclusters -A 2>/dev/null || echo "None found"
	@echo ""
	@echo "=== GarageBuckets ===" && kubectl get garagebuckets -A 2>/dev/null || echo "None found"
	@echo ""
	@echo "=== GarageKeys ===" && kubectl get garagekeys -A 2>/dev/null || echo "None found"
	@echo ""
	@echo "=== GarageNodes ===" && kubectl get garagenodes -A 2>/dev/null || echo "None found"
	@echo ""
	@echo "=== GarageAdminTokens ===" && kubectl get garageadmintokens -A 2>/dev/null || echo "None found"
	@echo ""
	@echo "=== Pods ===" && kubectl get pods -n garage-system 2>/dev/null || echo "None found"

.PHONY: dev-clean
dev-clean: ## Delete test resources from development cluster
	@kubectl delete -f hack/test-resources.yaml --ignore-not-found=true

.PHONY: dev-run
dev-run: install ## Run operator locally against the dev cluster (without deploying to cluster)
	@echo "Running operator locally. Press Ctrl+C to stop."
	@go run ./cmd/main.go

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	@if [ -d "$(HELM_CHART_DIR)/crds" ]; then \
		cp config/crd/bases/*.yaml $(HELM_CHART_DIR)/crds/ && \
		echo "CRDs synced to Helm chart"; \
	fi

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= garage-operator-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./test/e2e/ -v -ginkgo.v
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: test-e2e-bash
test-e2e-bash: ## Run comprehensive bash E2E tests (single cluster)
	@chmod +x hack/e2e-test.sh
	@hack/e2e-test.sh

.PHONY: test-e2e-bash-quick
test-e2e-bash-quick: ## Run quick bash E2E tests (single cluster, skip slow tests)
	@chmod +x hack/e2e-test.sh
	@hack/e2e-test.sh --quick

.PHONY: test-e2e-multicluster
test-e2e-multicluster: ## Run multi-cluster E2E tests (2 kind clusters)
	@chmod +x hack/e2e-multicluster-test.sh
	@hack/e2e-multicluster-test.sh

.PHONY: test-e2e-multicluster-no-cleanup
test-e2e-multicluster-no-cleanup: ## Run multi-cluster E2E tests without cleanup
	@chmod +x hack/e2e-multicluster-test.sh
	@hack/e2e-multicluster-test.sh --no-cleanup

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name garage-operator-builder
	$(CONTAINER_TOOL) buildx use garage-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm garage-operator-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Helm

HELM_CHART_DIR ?= charts/garage-operator
HELM_REGISTRY ?= ghcr.io/rajsinghtech/charts

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	helm lint $(HELM_CHART_DIR)

.PHONY: helm-template
helm-template: ## Render Helm chart templates locally
	helm template garage-operator $(HELM_CHART_DIR) --namespace garage-operator-system

.PHONY: helm-package
helm-package: ## Package Helm chart
	helm package $(HELM_CHART_DIR) -d dist/

.PHONY: helm-sync-crds
helm-sync-crds: manifests ## Sync CRDs from config/crd/bases to Helm chart
	cp config/crd/bases/*.yaml $(HELM_CHART_DIR)/crds/
	@echo "CRDs synced to Helm chart"

.PHONY: helm-install
helm-install: ## Install Helm chart to current cluster
	helm upgrade --install garage-operator $(HELM_CHART_DIR) \
		--namespace garage-operator-system \
		--create-namespace \
		--set image.tag=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm chart from current cluster
	helm uninstall garage-operator --namespace garage-operator-system

.PHONY: helm-push
helm-push: helm-package ## Push Helm chart to OCI registry (GHCR)
	helm push dist/garage-operator-*.tgz oci://$(HELM_REGISTRY)

.PHONY: helm-verify-crds
helm-verify-crds: ## Verify Helm chart CRDs match kustomize CRDs
	@echo "Checking if Helm chart CRDs match kustomize CRDs..."
	@MISMATCH=0; \
	for crd in config/crd/bases/*.yaml; do \
		filename=$$(basename "$$crd"); \
		helm_crd="$(HELM_CHART_DIR)/crds/$$filename"; \
		if [ ! -f "$$helm_crd" ]; then \
			echo "ERROR: $$filename missing from Helm chart crds/"; \
			MISMATCH=1; \
		elif ! diff -q "$$crd" "$$helm_crd" > /dev/null 2>&1; then \
			echo "ERROR: $$filename differs"; \
			MISMATCH=1; \
		else \
			echo "OK: $$filename"; \
		fi; \
	done; \
	if [ $$MISMATCH -eq 1 ]; then \
		echo ""; \
		echo "CRDs out of sync! Run 'make helm-sync-crds' to fix."; \
		exit 1; \
	fi; \
	echo "All CRDs are in sync."

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.7.1
CONTROLLER_TOOLS_VERSION ?= v0.19.0

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v1.61.0
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
