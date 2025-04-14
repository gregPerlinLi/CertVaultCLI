# Makefile for CertVault Application

# 定义变量
APP_NAME := certvault
BUILD_DIR := build
BIN_DIR := /usr/local/bin
SRC_FILES := $(shell find . -name "*.go")
GO_FLAGS := -v
LDFLAGS := -ldflags "-X main.version=$(shell git rev-parse --short HEAD)"

# 默认目标
all: build

# 编译目标
build: $(SRC_FILES)
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go mod tidy
	go build $(GO_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./main.go
	@echo "Build completed. Binary located at $(BUILD_DIR)/$(APP_NAME)"

# 安装目标
install: build
	@echo "Installing $(APP_NAME)..."
	@mkdir -p $(BIN_DIR)
	@cp $(BUILD_DIR)/$(APP_NAME) $(BIN_DIR)/
	@echo "$(APP_NAME) installed to $(BIN_DIR)"

# 清理目标
clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleanup completed."

# 测试目标
test:
	@echo "Running tests..."
	@go test ./... -cover -race
	@echo "Tests completed."

# 格式化代码
fmt:
	@echo "Formatting code..."
	@gofmt -s -w .
	@echo "Code formatting completed."

# 静态分析
lint:
	@echo "Running static analysis..."
	@golangci-lint run
	@echo "Static analysis completed."

# 帮助信息
help:
	@echo "Makefile Usage:"
	@echo "  make build     - Build the application"
	@echo "  make install   - Install the application binary"
	@echo "  make clean     - Clean up build artifacts"
	@echo "  make test      - Run unit tests"
	@echo "  make fmt       - Format the source code"
	@echo "  make lint      - Run static analysis on the code"
	@echo "  make help      - Show this help message"

.PHONY: all build install clean test fmt lint help
