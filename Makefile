CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS  ?=

empty :=
space := $(empty) $(empty)
CC_TAG := $(subst $(space),_,$(CC))

CMAKE_C_COMPILER ?= $(CC)
CMAKE_C_COMPILER_ARG1 ?=
CMAKE_C_COMPILER_TARGET ?=

CMAKE_CC_ARGS := -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER)
ifneq ($(strip $(CMAKE_C_COMPILER_ARG1)),)
CMAKE_CC_ARGS += -DCMAKE_C_COMPILER_ARG1=$(CMAKE_C_COMPILER_ARG1)
endif
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
CMAKE_CC_ARGS += -DCMAKE_C_COMPILER_TARGET=$(CMAKE_C_COMPILER_TARGET)
endif

LIBCSV_DIR    := third_party/libcsv
LIBCSV_SRC    := $(LIBCSV_DIR)/libcsv.c
LIBCSV_CFLAGS := -I$(LIBCSV_DIR)
JSONC_DIR     := third_party/json-c
JSONC_BUILD   := $(JSONC_DIR)/build-$(CC_TAG)
JSONC_LIB     := $(JSONC_BUILD)/libjson-c.a
JSONC_CFLAGS  := -Ithird_party -I$(JSONC_DIR) -I$(JSONC_BUILD)
CURL_DIR      := third_party/curl
CURL_BUILD    := $(CURL_DIR)/build-$(CC_TAG)
CURL_LIB      := $(CURL_BUILD)/lib/libcurl.a
CURL_CFLAGS   := -I$(CURL_DIR)/include

CFLAGS += $(LIBCSV_CFLAGS)
CFLAGS += $(JSONC_CFLAGS)
CFLAGS += $(CURL_CFLAGS)

TARGET := uboot_audit
SRC    := uboot_audit.c uboot_env_scan.c uboot_image_scan.c uboot_scan.c $(LIBCSV_SRC)

.PHONY: all env image static clean

all: $(TARGET)

env: $(TARGET)

image: $(TARGET)

$(JSONC_LIB):
	cmake -S $(JSONC_DIR) -B $(JSONC_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_APPS=OFF
	cmake --build $(JSONC_BUILD) --target json-c

$(CURL_LIB):
	cmake -S $(CURL_DIR) -B $(CURL_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DBUILD_TESTING=OFF -DCURL_USE_OPENSSL=OFF -DCURL_ZLIB=OFF -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DENABLE_ARES=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_DISABLE_NETRC=ON -DHTTP_ONLY=ON
	cmake --build $(CURL_BUILD) --target libcurl_static

$(TARGET): $(SRC) $(JSONC_LIB) $(CURL_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(JSONC_LIB) $(CURL_LIB) $(LDFLAGS) $(LDLIBS)

static: LDFLAGS += -static
static: all

clean:
	rm -f $(TARGET)
	rm -rf $(JSONC_DIR)/build*
	rm -rf $(CURL_DIR)/build*