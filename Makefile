ifneq ($(shell uname -s), Darwin)
	$(error "This Makefile is for MacOS cross-compilation only")
endif

ARCH := $(shell uname -m)
ifeq ($(ARCH), arm64)
	ARCH := aarch64
endif

CC := ${ARCH}-linux-musl-gcc
TARGET := target/aarch64-unknown-linux-musl/debug/execsnoop
OUTPUT ?= ${_WORK_DIR}/execsnoop

TARGET_CFG := --target=${ARCH}-unknown-linux-musl \
		--config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"

${TARGET}:

build-ebpf: ${TARGET}
	docker run -it -v ./src/bpf/:/src ghcr.io/eunomia-bpf/ecc-${ARCH}:latest

build: build-ebpf
	@echo "Building for ${ARCH}"
	cargo build ${TARGET_CFG}

	@echo "Copying binary to shared dir"
	cp ${TARGET} ${OUTPUT}
	chmod +x ${OUTPUT}

check:
	cargo check ${TARGET_CFG}

lint:
	cargo clippy ${TARGET_CFG}

clean:
	git clean -fx src/bpf/
	cargo clean
	rm -f ${OUTPUT}

.PHONY: clean build build-ebpf

