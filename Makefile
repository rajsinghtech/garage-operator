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
	@echo "  kubectl get garageclusters,garagebuckets,garagekeys -n garage-operator-system"

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
	@echo "=== Pods ===" && kubectl get pods -n garage-operator-system 2>/dev/null || echo "None found"

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
	@find config/crd/bases -maxdepth 1 -type f -name '*.yaml' -delete
	@find config/rbac -maxdepth 1 -type f -name 'role.yaml' -delete
	@find config/webhook -maxdepth 1 -type f -name 'manifests.yaml' -delete
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./api/..." paths="./internal/..." paths="./cmd/..." output:crd:artifacts:config=config/crd/bases
	@python3 hack/preserve-crd-compat-versions.py
	@if [ -d "$(HELM_CHART_DIR)/crd-bases" ]; then \
		find "$(HELM_CHART_DIR)/crd-bases" -maxdepth 1 -type f -name '*.yaml' -delete && \
		cp config/crd/bases/*.yaml $(HELM_CHART_DIR)/crd-bases/ && \
		echo "CRDs synced to Helm chart"; \
	fi
	@hack/generate-schemas.sh

.PHONY: schemas
schemas: ## Generate JSON schemas from CRDs for editor validation (also runs as part of manifests)
	@hack/generate-schemas.sh

.PHONY: validate-manifests
validate-manifests: schemas ## Validate sample manifests against JSON schemas (requires kubeconform)
	@command -v kubeconform >/dev/null 2>&1 || { echo "kubeconform not found. Install with: brew install kubeconform"; exit 1; }
	kubeconform -strict -summary \
		-kubernetes-version 1.25.0 \
		-schema-location default \
		-schema-location 'schemas/{{ .ResourceKind }}_{{ .ResourceAPIVersion }}.json' \
		-ignore-filename-pattern 'kustomization.yaml' \
		config/samples/*.yaml \
		config/samples/cosi/garagecluster-e2e.yaml

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./api/..." paths="./internal/..." paths="./cmd/..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v '/e2e$$') -coverprofile cover.out

.PHONY: test-race
test-race: setup-envtest ## Run non-E2E tests with the Go race detector.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test -race $$(go list ./... | grep -v '/e2e$$') -count=1 -timeout=15m

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= garage-operator-test-e2e
# Optional Kubernetes node image. CI pins this so Kind does not silently move
# the suite to a newer Kubernetes release when Kind's default changes.
KIND_NODE_IMAGE ?=
# Optional Kind config for topology-specific shards (for example, the
# multi-worker DaemonSet node-local-pool suite). Empty keeps Kind's one-node default.
KIND_CONFIG_E2E ?=
# GINKGO_LABEL_FILTER selects a subset of e2e specs by Ginkgo label (empty = all).
# CI sets this per matrix shard to split the suite across parallel Kind clusters.
GINKGO_LABEL_FILTER ?=
# The top-level Ordered blocks share cluster-scoped CRDs and the operator
# namespace. Keep their lifecycle order deterministic so a cleanup failure is
# reported at its owning block instead of becoming a later block's flake.
GINKGO_RANDOMIZE_ALL ?= false
# Records the exact kube-system UID of the cluster created by setup-test-e2e.
# cleanup-test-e2e refuses deletion unless the live cluster matches this record.
KIND_OWNERSHIP_FILE ?= $(LOCALBIN)/.kind-e2e-owner-$(KIND_CLUSTER)
# Dedicated kubeconfig isolates every E2E mutation from the user's mutable
# current context. It is retained with the ownership record after a failed run
# so cleanup can still authenticate the exact cluster it created.
KIND_KUBECONFIG_FILE ?= $(LOCALBIN)/.kind-e2e-kubeconfig-$(KIND_CLUSTER)
# A test run requires proof that its owned cluster was actually removed. Direct
# cleanup remains idempotent when no ownership record exists. If Kind reports a
# partially-created cluster, setup records ownership as soon as the live
# kube-system UID is available; cleanup can then remove that exact cluster.
REQUIRE_E2E_CLEANUP ?= false
E2E_DEBUG_DIR ?= /tmp/e2e-debug
# E2E_GO_TIMEOUT must stay BELOW the CI job's timeout-minutes. When the job
# timeout fires first the runner SIGKILLs the process group and Go never prints
# its goroutine dump, so a hung spec is indistinguishable from a slow one. Going
# through Go's own timeout instead yields a full stack trace naming the stuck
# spec.
#
# Sized against a measured floor, not guessed: removing a node that holds
# positive capacity is a drain, and the barrier must outlast Garage's
# delayed-resync window (BLOCK_GC_DELAY + 10s, ../garage src/block/manager.rs)
# before it can conclude no block is coming back. That makes one spec in the
# catch-all shard ~13m on its own, and the shard ~27m. At the previous 40m the
# margin was thin enough that a loaded runner tipped it over, which reports as an
# unattributed "test timed out" rather than as the slow spec.
E2E_GO_TIMEOUT ?= 50m
# Bound the Kind CLI independently of the GitHub job timeout. A stuck Docker
# API must not consume the entire E2E shard while its ownership record remains
# ambiguous.
KIND_QUERY_TIMEOUT ?= 15s
KIND_CREATE_TIMEOUT ?= 5m
KIND_DELETE_TIMEOUT ?= 5m

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up an isolated Kind cluster for e2e tests
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@command -v timeout >/dev/null 2>&1 || { \
		echo "timeout is required to bound Kind E2E operations."; \
		exit 1; \
	}
	@mkdir -p "$(dir $(KIND_OWNERSHIP_FILE))"
	@clusters="$$( timeout --foreground "$(KIND_QUERY_TIMEOUT)" "$(KIND)" get clusters 2>/dev/null )" || { \
			echo "ERROR: could not enumerate Kind clusters; preserving any existing ownership state"; \
			exit 1; \
		}; \
	if grep -Fqx -- "$(KIND_CLUSTER)" <<<"$$clusters"; then \
			echo "ERROR: refusing to reuse pre-existing Kind cluster '$(KIND_CLUSTER)'"; \
			exit 1; \
		else \
				rm -f "$(KIND_OWNERSHIP_FILE)" "$(KIND_KUBECONFIG_FILE)"; \
				echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
				create_status=0; \
				if [ -n "$(KIND_CONFIG_E2E)" ]; then \
						timeout --foreground "$(KIND_CREATE_TIMEOUT)" "$(KIND)" create cluster --name $(KIND_CLUSTER) --kubeconfig "$(KIND_KUBECONFIG_FILE)" --config "$(KIND_CONFIG_E2E)" $(if $(KIND_NODE_IMAGE),--image "$(KIND_NODE_IMAGE)") --wait 120s || create_status=$$?; \
					else \
						timeout --foreground "$(KIND_CREATE_TIMEOUT)" "$(KIND)" create cluster --name $(KIND_CLUSTER) --kubeconfig "$(KIND_KUBECONFIG_FILE)" $(if $(KIND_NODE_IMAGE),--image "$(KIND_NODE_IMAGE)") --wait 120s || create_status=$$?; \
				fi; \
				if [ "$$create_status" -ne 0 ]; then \
						partial_clusters="$$( timeout --foreground "$(KIND_QUERY_TIMEOUT)" "$(KIND)" get clusters 2>/dev/null || true )"; \
					if grep -Fqx -- "$(KIND_CLUSTER)" <<<"$$partial_clusters"; then \
						partial_uid="$$( KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get namespace kube-system \
							-o jsonpath='{.metadata.uid}' --request-timeout=10s 2>/dev/null || true )"; \
						if [ -n "$$partial_uid" ]; then \
							ownership_tmp="$$(mktemp "$(KIND_OWNERSHIP_FILE).tmp.XXXXXX")"; \
							printf '%s\n%s\n' "$(KIND_CLUSTER)" "$$partial_uid" > "$$ownership_tmp"; \
							mv -f -- "$$ownership_tmp" "$(KIND_OWNERSHIP_FILE)"; \
							echo "ERROR: Kind create failed after creating '$(KIND_CLUSTER)'; ownership recorded for cleanup"; \
						else \
							echo "ERROR: Kind create failed and left an unproven cluster named '$(KIND_CLUSTER)'; refusing deletion"; \
						fi; \
					else \
						echo "ERROR: Kind create failed before creating '$(KIND_CLUSTER)'"; \
					fi; \
					exit "$$create_status"; \
				fi; \
				if ! cluster_uid="$$( KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get namespace kube-system \
					-o jsonpath='{.metadata.uid}' --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" )"; then \
					echo "ERROR: could not query ownership of newly created Kind cluster '$(KIND_CLUSTER)'"; \
					echo "ERROR: preserving the cluster and kubeconfig for an ownership-gated cleanup attempt"; \
					exit 1; \
				fi; \
			if [ -z "$$cluster_uid" ]; then \
				echo "ERROR: could not record ownership of Kind cluster '$(KIND_CLUSTER)'"; \
				echo "ERROR: preserving the cluster and kubeconfig for an ownership-gated cleanup attempt"; \
				exit 1; \
			fi; \
			ownership_tmp="$$(mktemp "$(KIND_OWNERSHIP_FILE).tmp.XXXXXX")"; \
			printf '%s\n%s\n' "$(KIND_CLUSTER)" "$$cluster_uid" > "$$ownership_tmp"; \
			mv -f -- "$$ownership_tmp" "$(KIND_OWNERSHIP_FILE)"; \
	fi

.PHONY: test-e2e
test-e2e: manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	@setup_status=0; $(MAKE) setup-test-e2e || setup_status=$$?; \
	if [ "$$setup_status" -ne 0 ]; then \
		$(MAKE) dump-test-e2e || true; \
		: "cleanup is ownership-gated and safe to attempt after setup failure"; \
		$(MAKE) cleanup-test-e2e REQUIRE_E2E_CLEANUP=false || true; \
		exit "$$setup_status"; \
	fi; \
	status=0; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) \
		go test -tags=e2e ./test/e2e/ -v -ginkgo.v -ginkgo.randomize-all=$(GINKGO_RANDOMIZE_ALL) -ginkgo.label-filter="$(GINKGO_LABEL_FILTER)" -timeout $(E2E_GO_TIMEOUT) || status=$$?; \
	if [ "$$status" -ne 0 ]; then $(MAKE) dump-test-e2e || true; fi; \
	cleanup_status=0; $(MAKE) cleanup-test-e2e REQUIRE_E2E_CLEANUP=true || cleanup_status=$$?; \
	if [ "$$cleanup_status" -ne 0 ]; then $(MAKE) dump-test-e2e || true; fi; \
	if [ "$$status" -ne 0 ]; then exit "$$status"; fi; \
	exit "$$cleanup_status"

.PHONY: dump-test-e2e
dump-test-e2e: ## Capture suite-level diagnostics before cleanup (including BeforeSuite failures/timeouts)
	@mkdir -p "$(E2E_DEBUG_DIR)"; \
	timeout --foreground "$(KIND_QUERY_TIMEOUT)" "$(KIND)" get clusters > "$(E2E_DEBUG_DIR)/clusters.txt" 2>&1 || true; \
	if [ ! -f "$(KIND_OWNERSHIP_FILE)" ]; then \
		echo "No ownership record; refusing to inspect an unowned cluster." > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-ownership.txt"; \
		exit 0; \
	fi; \
	recorded_cluster="$$(sed -n '1p' "$(KIND_OWNERSHIP_FILE)")"; \
	recorded_uid="$$(sed -n '2p' "$(KIND_OWNERSHIP_FILE)")"; \
	live_uid="$$( KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get namespace kube-system -o jsonpath='{.metadata.uid}' --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" 2>/dev/null || true )"; \
	if [ "$$recorded_cluster" != "$(KIND_CLUSTER)" ] || [ -z "$$recorded_uid" ] || [ "$$live_uid" != "$$recorded_uid" ]; then \
		echo "Ownership mismatch; refusing to inspect a replacement cluster." > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-ownership.txt"; \
		exit 0; \
	fi; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get all -A -o wide --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-resources.txt" 2>&1 || true; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get garagecluster,garagenode,garagebucket,garagekey,garageadmintoken -A -o yaml --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-garage-resources.yaml" 2>&1 || true; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get events -A --sort-by=.lastTimestamp --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-events.txt" 2>&1 || true; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" logs deployment/garage-operator-controller-manager -n garage-operator-system --tail=2000 --pod-running-timeout=15s --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-operator.log" 2>&1 || true; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" logs deployment/garage-operator-controller-manager -n garage-operator-system --tail=2000 --previous --pod-running-timeout=15s --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" > "$(E2E_DEBUG_DIR)/$(KIND_CLUSTER)-operator-previous.log" 2>&1 || true

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@if [ ! -f "$(KIND_OWNERSHIP_FILE)" ]; then \
		echo "No ownership record for Kind cluster '$(KIND_CLUSTER)'; refusing deletion."; \
		if [ "$(REQUIRE_E2E_CLEANUP)" = true ]; then exit 1; fi; \
		exit 0; \
	fi; \
	recorded_cluster="$$(sed -n '1p' "$(KIND_OWNERSHIP_FILE)")"; \
	recorded_uid="$$(sed -n '2p' "$(KIND_OWNERSHIP_FILE)")"; \
	clusters_status=0; \
	clusters="$$( timeout --foreground "$(KIND_QUERY_TIMEOUT)" "$(KIND)" get clusters 2>/dev/null )" || clusters_status=$$?; \
	if [ "$$clusters_status" -ne 0 ]; then \
		echo "Could not enumerate Kind clusters; preserving ownership record and kubeconfig."; \
		exit "$$clusters_status"; \
	fi; \
	if ! grep -Fqx -- "$(KIND_CLUSTER)" <<<"$$clusters"; then \
		echo "Kind cluster '$(KIND_CLUSTER)' is already absent; removing its dedicated kubeconfig."; \
	rm -f "$(KIND_OWNERSHIP_FILE)" "$(KIND_KUBECONFIG_FILE)"; \
	exit 0; \
	fi; \
	if ! live_uid="$$( KUBECONFIG="$(KIND_KUBECONFIG_FILE)" $(KUBECTL) --context "kind-$(KIND_CLUSTER)" get namespace kube-system \
		-o jsonpath='{.metadata.uid}' --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" 2>/dev/null )"; then \
		echo "Could not query live Kind cluster '$(KIND_CLUSTER)'; preserving ownership record and kubeconfig."; \
		exit 1; \
	fi; \
	if [ "$$recorded_cluster" != "$(KIND_CLUSTER)" ] || [ -z "$$recorded_uid" ] || \
		[ -z "$$live_uid" ] || [ "$$live_uid" != "$$recorded_uid" ]; then \
		echo "Ownership record does not match live Kind cluster '$(KIND_CLUSTER)'; refusing deletion."; \
		if [ "$(REQUIRE_E2E_CLEANUP)" = true ]; then exit 1; fi; \
		exit 0; \
	fi; \
	KUBECONFIG="$(KIND_KUBECONFIG_FILE)" timeout --foreground "$(KIND_DELETE_TIMEOUT)" "$(KIND)" delete cluster --name $(KIND_CLUSTER); \
	remaining_status=0; \
	remaining="$$( timeout --foreground "$(KIND_QUERY_TIMEOUT)" "$(KIND)" get clusters 2>/dev/null )" || remaining_status=$$?; \
	if [ "$$remaining_status" -ne 0 ]; then \
		echo "Could not verify Kind cluster cleanup; preserving ownership record and kubeconfig."; \
		exit "$$remaining_status"; \
	fi; \
	if grep -Fqx -- "$(KIND_CLUSTER)" <<<"$$remaining"; then \
		echo "Kind cluster '$(KIND_CLUSTER)' still exists after delete; preserving ownership record and kubeconfig."; \
		exit 1; \
	fi; \
	rm -f "$(KIND_OWNERSHIP_FILE)" "$(KIND_KUBECONFIG_FILE)"

.PHONY: test-e2e-cluster
test-e2e-cluster: ## Run single-cluster E2E tests
	@chmod +x hack/e2e-cluster.sh
	@hack/e2e-cluster.sh

.PHONY: test-e2e-cosi
test-e2e-cosi: ## Run COSI E2E tests
	@chmod +x hack/e2e-cosi.sh
	@hack/e2e-cosi.sh

.PHONY: test-e2e-multicluster
test-e2e-multicluster: ## Run multi-cluster E2E tests (2 kind clusters)
	@chmod +x hack/e2e-multicluster.sh
	@hack/e2e-multicluster.sh

.PHONY: test-e2e-ipv6
test-e2e-ipv6: ## Run IPv6 dual-stack E2E tests (kind cluster with IPv6 primary pod IPs)
	@chmod +x hack/e2e-ipv6.sh
	@hack/e2e-ipv6.sh

.PHONY: test-e2e-external-gateway
test-e2e-external-gateway: ## Run external gateway E2E tests (gateway → Docker Garage node)
	@chmod +x hack/e2e-external-gateway.sh
	@hack/e2e-external-gateway.sh

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

.PHONY: install-hooks
install-hooks: ## Install git pre-commit hook to run lint locally before committing
	cp hack/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

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
	- $(CONTAINER_TOOL) buildx create --name garage-operator-builder
	$(CONTAINER_TOOL) buildx use garage-operator-builder
	$(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} .
	- $(CONTAINER_TOOL) buildx rm garage-operator-builder

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	@staging="$$(mktemp -d)"; \
	trap 'rm -rf -- "$$staging"' EXIT; \
	cp -a config "$$staging/config"; \
	cd "$$staging/config/manager" && "$(KUSTOMIZE)" edit set image controller=${IMG}; \
	"$(KUSTOMIZE)" build "$$staging/config/default" > "$(CURDIR)/dist/install.yaml"

##@ Helm

HELM_CHART_DIR ?= charts/garage-operator
HELM_REGISTRY ?= ghcr.io/rajsinghtech/charts
HELM_PACKAGE_DIR ?= dist
SOURCE_DATE_EPOCH ?= $(shell git show -s --format=%ct HEAD 2>/dev/null)

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	helm lint $(HELM_CHART_DIR)

.PHONY: helm-template
helm-template: ## Render Helm chart templates locally
	helm template garage-operator $(HELM_CHART_DIR) --namespace garage-operator-system

.PHONY: helm-package
helm-package: ## Package Helm chart
	@test -n "$(SOURCE_DATE_EPOCH)" && [[ "$(SOURCE_DATE_EPOCH)" =~ ^[0-9]+$$ ]] || { \
		echo "SOURCE_DATE_EPOCH must be a Unix timestamp"; exit 1; \
	}
	@mkdir -p "$(HELM_PACKAGE_DIR)"
	@staging="$$(mktemp -d)"; \
	trap 'rm -rf -- "$$staging"' EXIT; \
	chart="$$staging/$$(basename "$(HELM_CHART_DIR)")"; \
	cp -a "$(HELM_CHART_DIR)" "$$chart"; \
	find "$$chart" -exec touch --date="@$(SOURCE_DATE_EPOCH)" {} +; \
	helm package "$$chart" -d "$(HELM_PACKAGE_DIR)"

.PHONY: helm-sync-crd-bases
helm-sync-crd-bases: manifests ## Sync CRDs from config/crd/bases to Helm chart
	rm -f $(HELM_CHART_DIR)/crd-bases/*.yaml
	cp config/crd/bases/*.yaml $(HELM_CHART_DIR)/crd-bases/
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
	@chart_version="$$(awk '$$1 == "version:" { print $$2; exit }' "$(HELM_CHART_DIR)/Chart.yaml")"; \
	chart="$(HELM_PACKAGE_DIR)/$$(basename "$(HELM_CHART_DIR)")-$$chart_version.tgz"; \
	test -f "$$chart" || { echo "Packaged chart not found: $$chart"; exit 1; }; \
	helm push "$$chart" "oci://$(HELM_REGISTRY)"

.PHONY: chart-bump
chart-bump: ## Bump Helm chart version+appVersion and image tag. Usage: make chart-bump VERSION=v0.6.18
ifndef VERSION
	$(error VERSION is required. Usage: make chart-bump VERSION=v0.6.18)
endif
	@TAG=$$(echo "$(VERSION)" | sed 's/^v//'); \
	echo "Bumping chart version to $$TAG (appVersion $$TAG, image tag $(VERSION))"; \
	sed -i.bak "s/^version:.*/version: $$TAG/" $(HELM_CHART_DIR)/Chart.yaml && rm -f $(HELM_CHART_DIR)/Chart.yaml.bak; \
	sed -i.bak 's/^appVersion:.*/appVersion: "'$$TAG'"/' $(HELM_CHART_DIR)/Chart.yaml && rm -f $(HELM_CHART_DIR)/Chart.yaml.bak; \
	sed -i.bak 's|^  tag: ".*"|  tag: "$(VERSION)"|' $(HELM_CHART_DIR)/values.yaml && rm -f $(HELM_CHART_DIR)/values.yaml.bak; \
	echo "Done. Review and commit:"; \
	echo "  git diff $(HELM_CHART_DIR)/Chart.yaml $(HELM_CHART_DIR)/values.yaml"

.PHONY: release
release: ## Bump chart, commit, tag, and push in one atomic step. Usage: make release VERSION=v0.6.24
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=v0.6.24)
endif
	@if [ "$$(git branch --show-current)" != main ]; then \
		echo "ERROR: releases must be created from the main branch"; exit 1; \
	fi
	@if ! git diff --quiet || ! git diff --cached --quiet; then \
		echo "ERROR: working tree not clean, commit or stash first"; exit 1; \
	fi
	@git fetch --quiet origin main:refs/remotes/origin/main
	@if [ "$$(git rev-parse HEAD)" != "$$(git rev-parse origin/main)" ]; then \
		echo "ERROR: local main must exactly match origin/main before releasing"; exit 1; \
	fi
	$(MAKE) chart-bump VERSION=$(VERSION)
	@EXPECTED=$$(echo "$(VERSION)" | sed 's/^v//'); \
	CHART_VER=$$(grep '^version:' $(HELM_CHART_DIR)/Chart.yaml | awk '{print $$2}'); \
	APP_VER=$$(grep '^appVersion:' $(HELM_CHART_DIR)/Chart.yaml | sed 's/.*: *"\(.*\)".*/\1/'); \
	IMAGE_TAG=$$(grep '  tag: ' $(HELM_CHART_DIR)/values.yaml | sed 's/.*: *"\(.*\)".*/\1/'); \
	OK=true; \
	[ "$$CHART_VER" = "$$EXPECTED" ] || { echo "ERROR: chart version ($$CHART_VER) != $(VERSION)"; OK=false; }; \
	[ "$$APP_VER" = "$$EXPECTED" ] || { echo "ERROR: appVersion ($$APP_VER) != $(VERSION)"; OK=false; }; \
	[ "$$IMAGE_TAG" = "$(VERSION)" ] || { echo "ERROR: image.tag ($$IMAGE_TAG) != $(VERSION)"; OK=false; }; \
	$$OK || exit 1
	git add $(HELM_CHART_DIR)/Chart.yaml $(HELM_CHART_DIR)/values.yaml
	git commit -m "release: $(VERSION)"
	git tag $(VERSION)
	git push --atomic origin main $(VERSION)

.PHONY: helm-verify-version
helm-verify-version: ## Verify in-repo chart version matches the latest git tag
	@LATEST_TAG=$$(git describe --tags --abbrev=0 2>/dev/null || echo ""); \
	if [ -z "$$LATEST_TAG" ]; then \
		echo "No tags found, skipping check"; \
		exit 0; \
	fi; \
	EXPECTED=$$(echo "$$LATEST_TAG" | sed 's/^v//'); \
	CHART_VER=$$(grep '^version:' $(HELM_CHART_DIR)/Chart.yaml | awk '{print $$2}'); \
	APP_VER=$$(grep '^appVersion:' $(HELM_CHART_DIR)/Chart.yaml | sed 's/.*: *"\(.*\)".*/\1/'); \
	IMAGE_TAG=$$(grep '  tag: ' $(HELM_CHART_DIR)/values.yaml | sed 's/.*: *"\(.*\)".*/\1/'); \
	echo "Latest tag:    $$LATEST_TAG"; \
	echo "Chart version: $$CHART_VER"; \
	echo "appVersion:    $$APP_VER"; \
	echo "image.tag:    $$IMAGE_TAG"; \
	OK=true; \
	[ "$$CHART_VER" = "$$EXPECTED" ] || { echo "ERROR: chart version ($$CHART_VER) != tag ($$EXPECTED)"; OK=false; }; \
	[ "$$APP_VER" = "$$EXPECTED" ] || { echo "ERROR: appVersion ($$APP_VER) != tag ($$EXPECTED)"; OK=false; }; \
	[ "$$IMAGE_TAG" = "$$LATEST_TAG" ] || { echo "ERROR: image.tag ($$IMAGE_TAG) != tag ($$LATEST_TAG)"; OK=false; }; \
	$$OK && echo "All versions in sync." || exit 1

.PHONY: helm-verify-crd-bases
helm-verify-crd-bases: ## Verify Helm chart CRDs match kustomize CRDs
	@echo "Checking if Helm chart CRDs match kustomize CRDs..."
	@if ! git diff --no-index --exit-code -- config/crd/bases $(HELM_CHART_DIR)/crd-bases; then \
		echo ""; \
		echo "CRDs out of sync! Run 'make helm-sync-crd-bases' to fix."; \
		exit 1; \
	fi; \
	echo "All CRDs are in sync."

.PHONY: verify-generate
verify-generate: manifests generate ## Verify committed generated files (CRDs, Helm CRDs, JSON schemas, deepcopy) match the Go types.
	@GENERATED_STATUS="$$(git status --porcelain --untracked-files=all -- \
		'api/**/zz_generated.deepcopy.go' \
		config/crd/bases config/rbac/role.yaml config/webhook/manifests.yaml \
		charts/garage-operator/crd-bases schemas)"; \
	if [ -n "$$GENERATED_STATUS" ]; then \
		echo "ERROR: generated files are out of date with the Go types."; \
		echo "Run 'make manifests generate' and commit the result:"; \
		printf '%s\n' "$$GENERATED_STATUS"; \
		git --no-pager diff --stat -- \
			'api/**/zz_generated.deepcopy.go' \
			config/crd/bases config/rbac/role.yaml config/webhook/manifests.yaml \
			charts/garage-operator/crd-bases schemas; \
		exit 1; \
	fi; \
	echo "Generated files are in sync with the Go types."

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@# Use config/default so the conversion webhook clientConfig is rewritten to
	@# the release-scoped service (kustomize replacements). The bare config/crd
	@# output references webhook-service.system.svc, which doesn't exist.
	@"$(KUSTOMIZE)" build config/default 2>/dev/null \
	  | python3 hack/filter-crds.py \
	  | "$(KUBECTL)" --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" apply --server-side --force-conflicts -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" delete --ignore-not-found=$(ignore-not-found) --timeout=3m -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" apply --server-side --force-conflicts -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" --request-timeout="$(KUBECTL_REQUEST_TIMEOUT)" delete --ignore-not-found=$(ignore-not-found) --timeout=3m -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KUBECTL_REQUEST_TIMEOUT ?= 15s
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.7.1
CONTROLLER_TOOLS_VERSION ?= v0.20.1

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

# Exact envtest patch available from controller-tools. Keep this immutable so
# CI does not silently move when a newer Kubernetes 1.36 asset is published.
ENVTEST_K8S_VERSION ?= 1.36.2

SETUP_ENVTEST_VERSION ?= v0.24.0
GOLANGCI_LINT_VERSION ?= v2.12.2
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
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(SETUP_ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

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
