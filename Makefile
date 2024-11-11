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

${TARGET}:

build-ebpf: ${TARGET}
	docker run -it -v ./src/bpf/:/src ghcr.io/eunomia-bpf/ecc-${ARCH}:latest

build: build-ebpf
	@echo "Building for ${ARCH}"
	cargo build --target=${ARCH}-unknown-linux-musl \
		--config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"

	@echo "Copying binary to shared dir"
	cp ${TARGET} ${OUTPUT}
	chmod +x ${OUTPUT}

check:
	cargo check --target=${ARCH}-unknown-linux-musl \
		--config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"

clean:
	git clean -fx src/bpf/
	cargo clean
	rm -f ${OUTPUT}

.PHONY: clean build build-ebpf

