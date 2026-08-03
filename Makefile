BUILD_DIR = build
SLACK_WEBHOOK_URL ?=
USERNAME ?=

.PHONY: build deploy-lambda simulate clean fmt vet all

# all: format, vet, then build everything
all: fmt vet build

# build: compile the CLI and Lambda binaries and package the Lambda zip
build:
	@echo "==> Building CLI binary"
	@go build -o $(BUILD_DIR)/ghostiam.exe ./cmd/ghostiam/
	@echo "==> Building Lambda binary (linux/amd64)"
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/ghostiam-detector ./pkg/detect/lambda/
	@echo "==> Packaging Lambda zip"
	@cd $(BUILD_DIR) && zip ghostiam-detector.zip ghostiam-detector && cd ..

# deploy-lambda: build and deploy the detection infrastructure via Terraform
deploy-lambda: build
	@echo "==> Initializing Terraform"
	@cd terraform && terraform init
	@echo "==> Applying Terraform with SLACK_WEBHOOK_URL"
	@cd terraform && terraform apply -var="slack_webhook_url=$(SLACK_WEBHOOK_URL)"

# simulate: trigger the detection pipeline with a harmless API call
simulate:
	@echo "==> Simulating ghost activity as $(USERNAME)"
	@./$(BUILD_DIR)/ghostiam.exe simulate --username $(USERNAME)

# clean: remove build artifacts and Go caches
clean:
	@echo "==> Removing $(BUILD_DIR)/"
	@rm -rf $(BUILD_DIR)
	@echo "==> Running go clean"
	@go clean

# fmt: format Go source and Terraform configs
fmt:
	@echo "==> Formatting Go source"
	@gofmt -w .
	@echo "==> Formatting Terraform configs"
	@terraform fmt -recursive terraform/

# vet: static analysis and config formatting checks
vet:
	@echo "==> Running go vet"
	@go vet ./...
	@echo "==> Checking Terraform formatting"
	@terraform fmt -check -recursive terraform/
