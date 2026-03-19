CC      ?= gcc
HOSTCC  ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
HOSTCFLAGS ?= -O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
UNIT_TEST_CC ?= $(HOSTCC)
UNIT_TEST_CFLAGS ?= $(HOSTCFLAGS)
override UNIT_TEST_CFLAGS += -DELA_AGENT_UNIT_TESTS=1
UNIT_TEST_LDFLAGS ?=
LDFLAGS ?=
LDLIBS  ?=
JOBS    ?= 4
AUTOCONF ?= autoconf
TOOLS_CACHE_DIR ?= .cache/tools
ZIG_VERSION ?= 0.14.0

.DEFAULT_GOAL := all

HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m)
ZIG_IN_PATH := $(strip $(shell command -v zig 2>/dev/null))

ifeq ($(HOST_OS),linux)
ifeq ($(filter x86_64 amd64,$(HOST_ARCH)),)
ifeq ($(filter aarch64 arm64,$(HOST_ARCH)),)
ZIG_HOST_TRIPLE :=
ZIG_DOWNLOAD_HOST :=
else
ZIG_HOST_TRIPLE := aarch64-linux
ZIG_DOWNLOAD_HOST := linux-aarch64
endif
else
ZIG_HOST_TRIPLE := x86_64-linux
ZIG_DOWNLOAD_HOST := linux-x86_64
endif
else
ZIG_HOST_TRIPLE :=
ZIG_DOWNLOAD_HOST :=
endif

ZIG_CACHE_DIR := $(abspath $(TOOLS_CACHE_DIR))/zig/$(ZIG_VERSION)/$(ZIG_HOST_TRIPLE)
ZIG_BIN := $(if $(ZIG_IN_PATH),$(ZIG_IN_PATH),$(ZIG_CACHE_DIR)/zig)
NEEDS_ZIG := $(if $(findstring zig cc,$(CC)),1,$(if $(filter zig,$(notdir $(CMAKE_C_COMPILER))),1,))
LLVM_OBJCOPY_IN_PATH := $(strip $(shell command -v llvm-objcopy 2>/dev/null))
LLVM_OBJCOPY_BIN := $(if $(LLVM_OBJCOPY_IN_PATH),$(LLVM_OBJCOPY_IN_PATH),llvm-objcopy)

ifeq ($(NEEDS_ZIG),1)
OBJCOPY ?= $(LLVM_OBJCOPY_BIN)
else
OBJCOPY ?= objcopy
endif

ifeq ($(NEEDS_ZIG),1)
CC := $(patsubst zig %,$(ZIG_BIN) %,$(CC))
ifeq ($(filter zig,$(notdir $(CMAKE_C_COMPILER))),zig)
CMAKE_C_COMPILER := $(ZIG_BIN)
endif
endif

ELA_USE_READLINE ?= 1

ifneq (,$(findstring zig cc,$(CC)))
LDFLAGS += -Wl,--no-gc-sections
endif

ifneq ($(filter static,$(MAKECMDGOALS)),)
LDFLAGS += -static
endif

empty :=
space := $(empty) $(empty)
sanitize_tag = $(subst :,_,$(subst /,_,$(subst $(space),_,$(1))))
CC_TAG := $(call sanitize_tag,$(CC))

CMAKE_C_COMPILER ?= $(CC)
CMAKE_C_COMPILER_ARG1 ?=
CMAKE_C_COMPILER_TARGET ?=
# Avoid CMake executable try-compile link checks for cross targets that may fail
# during compiler probing (e.g. Zig + older CPU compatibility profiles).
CMAKE_TRY_COMPILE_TARGET_TYPE ?= STATIC_LIBRARY

OPENSSL_TARGET_TRIPLE ?= $(strip $(CMAKE_C_COMPILER_TARGET))
OPENSSL_CONFIGURE_TARGET ?=
OPENSSL_EXTRA_CONFIGURE_FLAGS ?=

ifeq ($(strip $(OPENSSL_CONFIGURE_TARGET)),)
ifneq ($(strip $(OPENSSL_TARGET_TRIPLE)),)
ifneq (,$(or \
  $(findstring x86_64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring aarch64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring mips64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring powerpc64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring riscv64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring s390x,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring sparc64,$(OPENSSL_TARGET_TRIPLE)), \
  $(findstring loongarch64,$(OPENSSL_TARGET_TRIPLE)) \
))
OPENSSL_CONFIGURE_TARGET := linux-generic64
else
OPENSSL_CONFIGURE_TARGET := linux-generic32
endif
endif
endif

CMAKE_CC_ARGS := -DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER)
ifneq ($(strip $(CMAKE_C_COMPILER_ARG1)),)
CMAKE_CC_ARGS += -DCMAKE_C_COMPILER_ARG1=$(CMAKE_C_COMPILER_ARG1)
endif
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
CMAKE_CC_ARGS += -DCMAKE_C_COMPILER_TARGET=$(CMAKE_C_COMPILER_TARGET)
 CMAKE_CC_ARGS += -DCMAKE_TRY_COMPILE_TARGET_TYPE=$(CMAKE_TRY_COMPILE_TARGET_TYPE)
endif
# CMake 3.20+ uses the compiler to generate .d dependency files (-MF flag).
# With zig cc and parallel builds the target directory does not yet exist when
# compile jobs start, causing "error opening '...o.d': No such file or
# directory".  Disable compiler-generated dep scanning for zig cc builds.
ifeq ($(NEEDS_ZIG),1)
CMAKE_CC_ARGS += -DCMAKE_DEPENDS_USE_COMPILER=FALSE
endif
WOLFSSL_CONFIGURE_HOST_ARG :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
WOLFSSL_CONFIGURE_HOST_ARG := --host=$(CMAKE_C_COMPILER_TARGET)
endif

ELA_ENABLE_WOLFSSL ?=
ifeq ($(strip $(ELA_ENABLE_WOLFSSL)),)
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(or $(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)),$(findstring ppc,$(CMAKE_C_COMPILER_TARGET))))
ELA_ENABLE_WOLFSSL := 1
else
ELA_ENABLE_WOLFSSL := 0
endif
else
ELA_ENABLE_WOLFSSL := 0
endif
endif

WOLFSSL_EXTRA_CONFIGURE_FLAGS :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(findstring mips64,$(CMAKE_C_COMPILER_TARGET)))
# wolfSSL's MIPS64 SP asm currently emits inline asm clobbers ($lo/$hi) that
# clang-as-zig rejects for these cross builds. Keep SP math enabled but force
# the portable C implementation for MIPS64 targets.
WOLFSSL_EXTRA_CONFIGURE_FLAGS += --disable-sp-asm
endif
ifneq (,$(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)))
ifeq (,$(findstring powerpc64,$(CMAKE_C_COMPILER_TARGET)))
# wolfSSL auto-enables ppc32-asm for 32-bit powerpc targets, but many embedded
# PowerPC CPUs (e.g. PPC603, PPC750, 4xx) do not implement the SPE or other
# extension instructions that the asm uses, causing an "Illegal instruction"
# crash at runtime.  Disable it to use the portable C implementation.
WOLFSSL_EXTRA_CONFIGURE_FLAGS += --disable-ppc32-asm
endif
endif
endif

# For 32-bit powerpc, autoconf cannot run test programs during cross-compilation
# and may fall back to the 64-bit host's sizeof(long)=8.  The resulting wolfSSL
# headers then embed SIZEOF_LONG=8, but zig cc (targeting 32-bit powerpc) sees
# sizeof(long)=4 and wolfSSL's compile-time assertion fires with
# "bad math long / long long settings".  Pre-seed the correct values via
# autoconf cache variables passed as trailing arguments to configure.
WOLFSSL_CONFIGURE_SIZEOF_ARGS :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)))
ifeq (,$(findstring powerpc64,$(CMAKE_C_COMPILER_TARGET)))
WOLFSSL_CONFIGURE_SIZEOF_ARGS := ac_cv_sizeof_long=4 ac_cv_sizeof_long_long=8
endif
endif
endif

# wolfSSL autoconf configure CFLAGS: force baseline ISA for 32-bit powerpc so
# zig cc (LLVM) does not emit instructions unsupported on embedded PowerPC cores.
WOLFSSL_CONFIGURE_CFLAGS :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)))
ifeq (,$(findstring powerpc64,$(CMAKE_C_COMPILER_TARGET)))
WOLFSSL_CONFIGURE_CFLAGS := -mcpu=ppc
endif
endif
endif

# Some bundled wolfSSL configure scripts in our pinned submodule revision reject
# libtool-style --enable-static/--disable-shared toggles even though we only
# consume the static archive. The build still produces src/.libs/libwolfssl.a
# without those options, so keep the configure invocation to the universally
# accepted feature toggles only.
WOLFSSL_LIBRARY_CONFIGURE_FLAGS :=

ELA_ENABLE_TPM2 ?= 1
TPM2_TSS_CONFIGURE_HOST_ARG :=
TPM2_TSS_CONFIGURE_BUILD_ARG :=
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
TPM2_TSS_CONFIGURE_HOST_ARG := --host=$(CMAKE_C_COMPILER_TARGET)
TPM2_TSS_CONFIGURE_BUILD_ARG := --build=$(shell cc -dumpmachine 2>/dev/null || gcc -dumpmachine 2>/dev/null || echo unknown-build)
endif

# curl SSL backend: wolfSSL for powerpc/ppc targets (OpenSSL triggers illegal
# instructions on powerpc), OpenSSL everywhere else.
ifeq ($(ELA_ENABLE_WOLFSSL),1)
CURL_CMAKE_SSL_ARGS = \
	-DCURL_USE_WOLFSSL=ON \
	-DCURL_USE_OPENSSL=OFF \
	-DWOLFSSL_INCLUDE_DIR="$(abspath $(WOLFSSL_INSTALL)/include)" \
	-DWOLFSSL_LIBRARY="$(abspath $(WOLFSSL_INSTALL)/lib/libwolfssl.a)"
CURL_SSL_DEP = $(WOLFSSL_LIB)
else
CURL_CMAKE_SSL_ARGS = \
	-DCURL_USE_OPENSSL=ON \
	-DOPENSSL_ROOT_DIR="$(abspath $(OPENSSL_INSTALL))" \
	-DOPENSSL_INCLUDE_DIR="$(abspath $(OPENSSL_INSTALL))/include" \
	-DOPENSSL_SSL_LIBRARY="$(abspath $(OPENSSL_SSL_LIB))" \
	-DOPENSSL_CRYPTO_LIBRARY="$(abspath $(OPENSSL_LIB))"
CURL_SSL_DEP = $(OPENSSL_SSL_LIB)
endif

CURL_CMAKE_ARGS := $(CMAKE_CC_ARGS)
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
# curl's CMake feature probes are fragile for cross targets under zig cc.
CURL_CMAKE_ARGS += -D_CURL_PREFILL=ON
ifneq (,$(findstring linux,$(CMAKE_C_COMPILER_TARGET)))
# musl uses the POSIX strerror_r signature; curl's probe can become ambiguous
# when cross-compiling these Zig Linux targets and then trips a hard preprocessor error.
CURL_CMAKE_ARGS += -DHAVE_POSIX_STRERROR_R=1 -DHAVE_GLIBC_STRERROR_R=0
endif
endif

# When building curl for 32-bit powerpc with wolfSSL, curl's cmake detects
# sizeof(long)=4 and emits "#define SIZEOF_LONG 4" in curl_config.h, but does
# not check sizeof(long long) so SIZEOF_LONG_LONG is never defined.  curl_setup.h
# includes curl_config.h before any wolfSSL headers; wolfSSL's types.h then sees
# SIZEOF_LONG=4 with no SIZEOF_LONG_LONG and none of the CTC_SETTINGS enum
# branches match, triggering "#error bad math long / long long settings".
# Pre-define SIZEOF_LONG_LONG=8 via CMAKE_C_FLAGS to supply the missing value.
#
# When building curl with wolfSSL, also explicitly define OPENSSL_EXTRA so that
# curl's wolfssl.c can see all the OpenSSL-compat function declarations in
# wolfssl/ssl.h (wolfSSL_CTX_set_cert_store, wolfSSL_CTX_get_cert_store,
# wolfSSL_CTX_set1_curves_list, SSL_CTX_set_cipher_list, etc.).  wolfSSL is
# built with --enable-opensslextra so the implementations are present in
# libwolfssl.a; this flag makes the declarations visible without relying on the
# installed options.h being picked up before settings.h processes its guards.
CURL_EXTRA_CFLAGS :=
ifeq ($(ELA_ENABLE_WOLFSSL),1)
CURL_EXTRA_CFLAGS += -DOPENSSL_EXTRA
ifneq (,$(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)))
ifeq (,$(findstring powerpc64,$(CMAKE_C_COMPILER_TARGET)))
CURL_EXTRA_CFLAGS += -DSIZEOF_LONG_LONG=8
endif
endif
endif
# For 32-bit powerpc, force baseline ISA so zig cc (LLVM) does not emit isel /
# lwsync instructions that older embedded PowerPC cores (Book E, 603, 750, 4xx)
# do not implement, which would cause an "Illegal instruction" crash at runtime.
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)))
ifeq (,$(findstring powerpc64,$(CMAKE_C_COMPILER_TARGET)))
CURL_EXTRA_CFLAGS += -mcpu=ppc
endif
endif
endif
ifneq ($(strip $(CURL_EXTRA_CFLAGS)),)
CURL_CMAKE_ARGS += -DCMAKE_C_FLAGS="$(CURL_EXTRA_CFLAGS)"
endif

JSONC_CMAKE_ARGS := $(CMAKE_CC_ARGS)

LIBSSH_EXTRA_CFLAGS :=
LIBSSH_CMAKE_ARGS := $(CMAKE_CC_ARGS)
LIBSSH_EXTRA_CFLAGS += -DOPENSSL_ENGINE_STUBS
ifneq ($(strip $(LIBSSH_EXTRA_CFLAGS)),)
LIBSSH_CMAKE_ARGS += -DCMAKE_C_FLAGS="$(LIBSSH_EXTRA_CFLAGS)"
endif
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
# Use a compiler launcher for libssh cross-builds so we can sand off a few
# probe/flag incompatibilities without patching bundled third_party sources.
# This is also where we inject any per-file compatibility workarounds needed by
# stricter cross compilers.
LIBSSH_CMAKE_ARGS += -DCMAKE_C_COMPILER_LAUNCHER=python3\;$(abspath tools/libssh_cc_launcher.py)
endif
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
# libssh's FIPS_mode() probe can mis-detect availability when cross-compiling
# against our bundled OpenSSL 3.x, which then breaks the actual compile because
# OpenSSL 3 removed the legacy FIPS_mode() declaration. Seed the cache result so
# libssh uses its OpenSSL 3 code path instead.
LIBSSH_CMAKE_ARGS += -DHAVE_OPENSSL_FIPS_MODE=0
endif
ifneq ($(findstring zig cc,$(CC)),)
# Clang treats old-style function definitions as strict-prototypes warnings, and
# libssh promotes that warning to an error in some cross builds. Keep the build
# otherwise strict, but avoid failing on this third-party warning in submodule
# sources we do not patch locally.
LIBSSH_EXTRA_CFLAGS += -Wno-strict-prototypes
LIBSSH_CMAKE_ARGS := $(CMAKE_CC_ARGS)
LIBSSH_CMAKE_ARGS += -DCMAKE_C_FLAGS="$(LIBSSH_EXTRA_CFLAGS)"
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
LIBSSH_CMAKE_ARGS += -DCMAKE_C_COMPILER_LAUNCHER=python3\;$(abspath tools/libssh_cc_launcher.py)
endif
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
LIBSSH_CMAKE_ARGS += -DHAVE_OPENSSL_FIPS_MODE=0
endif
endif

LIBCSV_DIR    := third_party/libcsv
LIBCSV_SRC    := $(LIBCSV_DIR)/libcsv.c
LIBCSV_CFLAGS := -I$(LIBCSV_DIR)
LIBUBOOTENV_DIR := third_party/libubootenv
LIBUBOOTENV_BUILD := $(LIBUBOOTENV_DIR)/build-$(CC_TAG)
LIBUBOOTENV_LIB := $(LIBUBOOTENV_BUILD)/src/libubootenv.a
LIBUBOOTENV_CFLAGS := -I$(LIBUBOOTENV_DIR)/src
LIBEFIVAR_DIR := third_party/libefivar
LIBEFIVAR_BUILD_STAMP := $(LIBEFIVAR_DIR)/.ela-build-$(CC_TAG)
LIBEFIVAR_LIB := $(LIBEFIVAR_DIR)/src/libefivar.a
LIBEFIVAR_CFLAGS := -I$(LIBEFIVAR_DIR)/src/include
ZLIB_DIR      := third_party/zlib
ZLIB_BUILD    := $(ZLIB_DIR)/build-$(CC_TAG)
ZLIB_LIB      := $(ZLIB_BUILD)/libz.a
ZLIB_CFLAGS   := -I$(ZLIB_DIR) -I$(ZLIB_BUILD)
ZLIB_EXTRA_CFLAGS :=
LIBUBOOTENV_EXTRA_CFLAGS := -I$(abspath compat) -I$(abspath $(ZLIB_DIR)) -I$(abspath $(ZLIB_BUILD)) -Wno-switch
JSONC_DIR     := third_party/json-c
JSONC_BUILD   := $(JSONC_DIR)/build-$(CC_TAG)
JSONC_LIB     := $(JSONC_BUILD)/libjson-c.a
JSONC_CFLAGS  := -Ithird_party -I$(JSONC_DIR) -I$(JSONC_BUILD)
CURL_DIR      := third_party/curl
CURL_BUILD    := $(CURL_DIR)/build-$(CC_TAG)
CURL_LIB      := $(CURL_BUILD)/lib/libcurl.a
CURL_CFLAGS   := -I$(CURL_DIR)/include
LIBSSH_DIR    := third_party/libssh
LIBSSH_BUILD  := $(LIBSSH_DIR)/build-$(CC_TAG)
# libssh's CMakeLists places the ssh-static archive under src/ on non-MSVC
# builds because OUTPUT_SUFFIX is empty in that case.
LIBSSH_LIB    := $(LIBSSH_BUILD)/src/libssh.a
LIBSSH_CFLAGS := -I$(LIBSSH_DIR)/include -I$(LIBSSH_BUILD)/include -I$(LIBSSH_BUILD)
TPM2_TSS_DIR := third_party/tpm2-tss
TPM2_TSS_BUILD := $(TPM2_TSS_DIR)/build-$(CC_TAG)
TPM2_TSS_BUILD_STAMP := $(TPM2_TSS_BUILD)/.ela-build-stamp
TPM2_TSS_CFLAGS := -I$(TPM2_TSS_DIR)/include
TPM2_TSS_RC_LIB := $(TPM2_TSS_BUILD)/src/tss2-rc/.libs/libtss2-rc.a
TPM2_TSS_MU_LIB := $(TPM2_TSS_BUILD)/src/tss2-mu/.libs/libtss2-mu.a
TPM2_TSS_SYS_LIB := $(TPM2_TSS_BUILD)/src/tss2-sys/.libs/libtss2-sys.a
TPM2_TSS_ESYS_LIB := $(TPM2_TSS_BUILD)/src/tss2-esys/.libs/libtss2-esys.a
TPM2_TSS_TCTI_DEVICE_LIB := $(TPM2_TSS_BUILD)/src/tss2-tcti/.libs/libtss2-tcti-device.a
TPM2_TSS_BUILD_CFLAGS ?= -O2 -Wno-unused-variable
TPM2_TSS_ZIG_GLOBAL_CACHE := $(abspath .cache/zig-global)
WOLFSSL_DIR     := third_party/wolfssl
WOLFSSL_BUILD   := $(WOLFSSL_DIR)/build-$(CC_TAG)
WOLFSSL_INSTALL := $(WOLFSSL_BUILD)/install
WOLFSSL_LIB     := $(WOLFSSL_BUILD)/src/.libs/libwolfssl.a
WOLFSSL_CFLAGS  := -I$(WOLFSSL_DIR) -I$(WOLFSSL_BUILD)
OPENSSL_DIR   := third_party/openssl
OPENSSL_BUILD := $(OPENSSL_DIR)/build-$(CC_TAG)
OPENSSL_INSTALL := $(OPENSSL_BUILD)/install
OPENSSL_CMAKE_DIR := $(OPENSSL_INSTALL)/lib/cmake/OpenSSL
OPENSSL_SSL_LIB := $(OPENSSL_INSTALL)/lib/libssl.a
OPENSSL_LIB   := $(OPENSSL_INSTALL)/lib/libcrypto.a
OPENSSL_CFLAGS := -I$(OPENSSL_INSTALL)/include
# Disable OpenSSL features not used by this project to reduce binary size.
# Legacy provider (RC4, Blowfish, IDEA, etc.), compression, obsolete protocols,
# regional algorithms (SM2/3/4, GOST, ARIA, SEED), post-quantum (not yet used),
# and unused KDFs/modes are all excluded.
OPENSSL_DISABLE_FEATURES := \
	no-legacy no-comp no-srp no-psk \
	no-ct no-cms no-ts no-srtp no-srtpkdf no-dtls no-sctp \
	no-scrypt no-nextprotoneg no-quic no-cmp no-rfc3779 \
	no-ssl-trace no-weak-ssl-ciphers \
	no-gost no-aria no-seed no-camellia no-cast \
	no-bf no-idea no-rc2 no-rc4 no-rc5 \
	no-sm2 no-sm2-precomp no-sm3 no-sm4 \
	no-md2 no-md4 no-mdc2 no-whirlpool no-rmd160 no-blake2 \
	no-ml-dsa no-ml-kem no-slh-dsa no-lms \
	no-x942kdf no-x963kdf no-pvkkdf no-snmpkdf no-krb5kdf \
	no-ocb no-siv
NCURSES_DIR   := third_party/ncurses
NCURSES_BUILD_STAMP := $(NCURSES_DIR)/.ela-build-$(CC_TAG)
NCURSES_LIB_DIR := $(NCURSES_DIR)/lib
NCURSES_LIB   := $(NCURSES_LIB_DIR)/libncurses.a
NCURSES_TINFO_LIB := $(NCURSES_LIB_DIR)/libtinfo.a
READLINE_DIR  := third_party/readline
READLINE_BUILD_STAMP := $(READLINE_DIR)/.ela-build-$(CC_TAG)
READLINE_LIB  := $(READLINE_DIR)/libreadline.a
READLINE_HISTORY_LIB := $(READLINE_DIR)/libhistory.a
READLINE_BUILD_CFLAGS ?= -O2 -Wno-incompatible-pointer-types
LIBEFIVAR_HOST_CFLAGS ?= -O2 -std=gnu11 -funsigned-char -fvisibility=hidden
LIBEFIVAR_HOST_CPPFLAGS ?= -I$(abspath $(LIBEFIVAR_DIR))/src/include -DEFIVAR_BUILD_ENVIRONMENT
GENERATED_DIR := generated
LIBEFIVAR_HOST_LDFLAGS ?= $(LIBEFIVAR_HOST_CFLAGS)
LIBEFIVAR_LINK_LIB := $(GENERATED_DIR)/libefivar-link-$(CC_TAG).a
LIBEFIVAR_REPACK_DIR := $(GENERATED_DIR)/libefivar-repack-$(CC_TAG)
DEFAULT_CA_BUNDLE_PEM := $(GENERATED_DIR)/cacert.pem
CA_BUNDLE_URL ?= https://curl.se/ca/cacert.pem
CA_BUNDLE_PEM ?= $(DEFAULT_CA_BUNDLE_PEM)
GENERATED_CA_SRC := $(GENERATED_DIR)/ela_default_ca_bundle.c
AGENT_UNIT_TEST_BIN := $(GENERATED_DIR)/agent_unit_tests
COVERAGE_DIR := $(GENERATED_DIR)/coverage
AGENT_C_COVERAGE_INFO := $(COVERAGE_DIR)/agent-c.lcov.info
AGENT_C_COVERAGE_HTML := $(COVERAGE_DIR)/html
COVERAGE_CC ?= gcc
COVERAGE_EXTRA_CFLAGS ?= -O0 -g --coverage
COVERAGE_EXTRA_HOSTCFLAGS ?= -O0 -g --coverage
COVERAGE_EXTRA_UNIT_TEST_CFLAGS ?= -O0 -g --coverage
COVERAGE_EXTRA_LDFLAGS ?= --coverage
AGENT_UNIT_TEST_SRC := \
	tests/unit/agent/main.c \
	tests/unit/agent/test_harness.c \
	tests/unit/agent/test_str_util.c \
	tests/unit/agent/test_isa_util.c \
	tests/unit/agent/test_crc32_util.c \
	tests/unit/agent/test_http_uri_util.c \
	tests/unit/agent/test_command_parse_util.c \
	tests/unit/agent/test_record_formatter.c \
	tests/unit/agent/test_list_files_filter_util.c \
	tests/unit/agent/test_lifecycle_formatter.c \
	tests/unit/agent/test_ela_conf_util.c \
	tests/unit/agent/test_interactive_parse_util.c \
	tests/unit/agent/test_file_scan_formatter.c \
	tests/unit/agent/test_tpm2_pcr_parse_util.c \
	tests/unit/agent/test_ws_url_util.c \
	tests/unit/agent/test_remote_copy_util.c \
	tests/unit/agent/test_orom_util.c \
	tests/unit/agent/test_http_protocol_util.c \
	tests/unit/agent/test_tcp_parse_util.c \
	tests/unit/agent/test_tcp_runtime_util.c \
	tests/unit/agent/test_api_key_util.c \
	tests/unit/agent/test_command_io_util.c \
	tests/unit/agent/test_ws_frame_util.c \
	tests/unit/agent/test_ssh_parse_util.c \
	tests/unit/agent/test_tpm2_output_format_util.c \
	tests/unit/agent/test_tpm2_command_util.c \
	tests/unit/agent/test_transfer_parse_util.c \
	tests/unit/agent/test_ws_session_util.c \
	tests/unit/agent/test_uboot_command_extract_util.c \
	tests/unit/agent/test_uboot_image_format_util.c \
	tests/unit/agent/test_uboot_image_record_util.c \
	tests/unit/agent/test_uboot_env_util.c \
	tests/unit/agent/test_uboot_env_record_util.c \
	tests/unit/agent/test_uboot_audit_util.c \
	tests/unit/agent/test_linux_dmesg_util.c \
	tests/unit/agent/test_http_ws_policy_util.c \
	tests/unit/agent/test_uboot_security_audit_util.c \
	tests/unit/agent/test_uboot_env_format_util.c \
	tests/unit/agent/test_uboot_env_scan_util.c \
	tests/unit/agent/test_http_client_parse_util.c \
	tests/unit/agent/test_http_client_body_util.c \
	tests/unit/agent/test_http_client_protocol_util.c \
	tests/unit/agent/test_http_client_runtime_util.c \
	tests/unit/agent/test_ws_connect_util.c \
	tests/unit/agent/test_ws_interactive_util.c \
	tests/unit/agent/test_ws_recv_util.c \
	tests/unit/agent/test_remote_copy_cmd_util.c \
	tests/unit/agent/test_script_exec_util.c \
	tests/unit/agent/test_interactive_util.c \
	tests/unit/agent/test_linux_execute_command_util.c
AGENT_UNIT_TEST_DEPS := \
	agent/util/str_util.c \
	agent/util/isa_util.c \
	agent/util/crc32_util.c \
	agent/util/http_uri_util.c \
	agent/util/command_parse_util.c \
	agent/util/record_formatter.c \
	agent/util/list_files_filter_util.c \
	agent/util/lifecycle_formatter.c \
	agent/util/interactive_parse_util.c \
	agent/util/file_scan_formatter.c \
	agent/util/tpm2_pcr_parse_util.c \
	agent/util/remote_copy_util.c \
	agent/util/orom_util.c \
	agent/util/http_protocol_util.c \
	agent/util/command_io_util.c \
	agent/util/ssh_parse_util.c \
	agent/util/tpm2_output_format_util.c \
	agent/util/tpm2_command_util.c \
	agent/util/transfer_parse_util.c \
	agent/linux/linux_dmesg_util.c \
	agent/linux/remote_copy_cmd_util.c \
	agent/net/ela_conf_util.c \
	agent/net/ws_url_util.c \
	agent/net/ws_connect_util.c \
	agent/net/ws_interactive_util.c \
	agent/net/tcp_parse_util.c \
	agent/net/tcp_runtime_util.c \
	agent/net/api_key_util.c \
	agent/net/ws_frame_util.c \
	agent/net/ws_session_util.c \
	agent/net/http_ws_policy_util.c \
	agent/net/http_client_parse_util.c \
	agent/net/http_client_body_util.c \
	agent/net/http_client_protocol_util.c \
	agent/net/http_client_runtime_util.c \
	agent/net/ws_recv_util.c \
	agent/uboot/env/uboot_env_format_util.c \
	agent/uboot/env/uboot_env_record_util.c \
	agent/uboot/env/uboot_env_util.c \
	agent/uboot/env/uboot_env_scan_util.c \
	agent/uboot/audit-rules/uboot_audit_util.c \
	agent/uboot/uboot_security_audit_util.c \
	agent/uboot/image/uboot_command_extract_util.c \
	agent/uboot/image/uboot_image_format_util.c \
	agent/uboot/image/uboot_image_record_util.c \
	agent/linux/linux_execute_command_util.c \
	agent/shell/script_exec_util.c \
	agent/shell/interactive_util.c \
	agent/util/str_util.h \
	agent/util/isa_util.h \
	agent/util/http_uri_util.h \
	agent/util/command_parse_util.h \
	agent/util/record_formatter.h \
	agent/util/list_files_filter_util.h \
	agent/util/lifecycle_formatter.h \
	agent/util/interactive_parse_util.h \
	agent/util/file_scan_formatter.h \
	agent/util/tpm2_pcr_parse_util.h \
	agent/util/remote_copy_util.h \
	agent/util/orom_util.h \
	agent/util/http_protocol_util.h \
	agent/util/command_io_util.h \
	agent/util/ssh_parse_util.h \
	agent/util/tpm2_output_format_util.h \
	agent/util/tpm2_command_util.h \
	agent/util/transfer_parse_util.h \
	agent/linux/linux_dmesg_util.h \
	agent/linux/remote_copy_cmd_util.h \
	agent/linux/linux_execute_command_util.h \
	agent/net/ela_conf_util.h \
	agent/net/ela_conf.h \
	agent/net/ws_url_util.h \
	agent/net/tcp_parse_util.h \
	agent/net/tcp_runtime_util.h \
	agent/net/api_key_util.h \
	agent/net/ws_frame_util.h \
	agent/net/ws_session_util.h \
	agent/net/http_ws_policy_util.h \
	agent/net/http_client_parse_util.h \
	agent/net/ws_recv_util.h \
	agent/uboot/env/uboot_env_util.h \
	agent/uboot/env/uboot_env_scan_util.h \
	agent/uboot/audit-rules/uboot_audit_util.h \
	agent/uboot/uboot_security_audit_util.h \
	agent/uboot/image/uboot_command_extract_util.h \
	agent/uboot/image/uboot_image_internal.h \
	agent/embedded_linux_audit_cmd.h

ZLIB_CMAKE_ARGS := $(CMAKE_CC_ARGS)
ifneq ($(strip $(ZLIB_EXTRA_CFLAGS)),)
ZLIB_CMAKE_ARGS += -DCMAKE_C_FLAGS="$(ZLIB_EXTRA_CFLAGS)"
endif

CFLAGS += $(LIBCSV_CFLAGS)
CFLAGS += $(LIBUBOOTENV_CFLAGS)
CFLAGS += $(LIBEFIVAR_CFLAGS)
CFLAGS += $(ZLIB_CFLAGS)
CFLAGS += $(JSONC_CFLAGS)
CFLAGS += $(CURL_CFLAGS)
CFLAGS += $(LIBSSH_CFLAGS)
ifeq ($(ELA_ENABLE_WOLFSSL),1)
CFLAGS += $(WOLFSSL_CFLAGS)
CFLAGS += -DELA_HAS_WOLFSSL=1
# Suppress -Wmacro-redefined: wolfSSL's OpenSSL-compat layer and the real OpenSSL
# headers both define SSL_VERIFY_PEER, SSL_ERROR_NONE, etc., which is expected
# when both are present in the same binary (wolfSSL for TLS, OpenSSL for libssh).
CFLAGS += -Wno-macro-redefined
# Suppress "No configuration for wolfSSL detected" and "harden options" warnings
# that fire when wolfSSL headers are included outside of the wolfSSL build tree.
CFLAGS += -DWOLFSSL_CUSTOM_CONFIG -DWC_NO_HARDEN
endif
ifeq ($(ELA_ENABLE_TPM2),1)
CFLAGS += $(TPM2_TSS_CFLAGS)
CFLAGS += -DELA_HAS_TPM2=1
endif
CFLAGS += $(OPENSSL_CFLAGS)
CFLAGS += -I.
CFLAGS += -Iagent

# Force baseline PowerPC ISA for 32-bit powerpc cross-builds so zig cc (LLVM)
# does not generate isel/lwsync instructions absent from older embedded cores.
ifneq ($(strip $(CMAKE_C_COMPILER_TARGET)),)
ifneq (,$(findstring powerpc,$(CMAKE_C_COMPILER_TARGET)))
ifeq (,$(findstring powerpc64,$(CMAKE_C_COMPILER_TARGET)))
CFLAGS += -mcpu=ppc
endif
endif
endif

ifeq ($(ELA_USE_READLINE),1)
CFLAGS += -DELA_HAS_READLINE -I$(READLINE_DIR)
LDLIBS += $(READLINE_LIB) $(READLINE_HISTORY_LIB) $(NCURSES_LIB) $(NCURSES_TINFO_LIB)
READLINE_DEPS := $(NCURSES_BUILD_STAMP) $(READLINE_BUILD_STAMP)
else
READLINE_DEPS :=
endif

# Allow callers (e.g. coverage-agent-c) to append extra flags without
# expanding CC-path-dependent variables in the outer make context.
CFLAGS           += $(CFLAGS_APPEND)
HOSTCFLAGS       += $(HOSTCFLAGS_APPEND)
UNIT_TEST_CFLAGS += $(UNIT_TEST_CFLAGS_APPEND)

TARGET := embedded_linux_audit
SRC    := agent/embedded_linux_audit.c agent/shell/interactive.c agent/shell/interactive_util.c agent/shell/script_exec.c agent/shell/script_exec_util.c agent/lifecycle.c agent/util/str_util.c agent/util/isa_util.c agent/util/crc32_util.c agent/util/http_uri_util.c agent/util/command_parse_util.c agent/util/record_formatter.c agent/util/list_files_filter_util.c agent/util/lifecycle_formatter.c agent/util/interactive_parse_util.c agent/util/file_scan_formatter.c agent/util/tpm2_pcr_parse_util.c agent/util/remote_copy_util.c agent/util/orom_util.c agent/util/http_protocol_util.c agent/util/command_io_util.c agent/util/ssh_parse_util.c agent/util/tpm2_output_format_util.c agent/util/tpm2_command_util.c agent/util/transfer_parse_util.c agent/net/tcp_util.c agent/net/tcp_runtime_util.c agent/net/http_client.c agent/net/http_client_parse_util.c agent/net/http_client_body_util.c agent/net/http_client_protocol_util.c agent/net/http_client_runtime_util.c agent/net/ela_conf.c agent/net/ela_conf_util.c agent/net/ws_url_util.c agent/net/ws_connect_util.c agent/net/ws_interactive_util.c agent/net/tcp_parse_util.c agent/net/api_key_util.c agent/net/ws_frame_util.c agent/net/ws_recv_util.c agent/net/ws_session_util.c agent/net/http_ws_policy_util.c agent/device/device_scan.c agent/uboot/env/uboot_env_cmd.c agent/uboot/env/uboot_env_format_util.c agent/uboot/env/uboot_env_record_util.c agent/uboot/env/uboot_env_util.c agent/uboot/env/uboot_env_scan_util.c agent/uboot/env/uboot_env_read_vars_cmd.c agent/uboot/env/uboot_env_write_vars_cmd.c agent/uboot/env/uboot_env_write_op.c agent/uboot/uboot_image_cmd.c agent/uboot/image/uboot_image_format_util.c agent/uboot/image/uboot_image_record_util.c agent/uboot/image/uboot_image_pull_cmd.c agent/uboot/image/uboot_image_find_address_cmd.c agent/uboot/image/uboot_image_list_commands_cmd.c agent/uboot/image/uboot_command_extract_util.c agent/uboot/uboot_security_audit_cmd.c agent/uboot/uboot_security_audit_util.c agent/uboot/audit/uboot_audit_output.c agent/uboot/audit-rules/uboot_audit_util.c agent/linux/linux_dmesg_cmd.c agent/linux/linux_dmesg_util.c agent/linux/linux_dmesg_watch_cmd.c agent/linux/linux_download_file_cmd.c agent/linux/linux_execute_command_cmd.c agent/linux/linux_execute_command_util.c agent/linux/linux_grep_cmd.c agent/linux/linux_list_files_cmd.c agent/linux/linux_list_symlinks_cmd.c agent/linux/linux_remote_copy_cmd.c agent/linux/remote_copy_cmd_util.c agent/linux/linux_ssh_cmd.c agent/tpm2/tpm2_cmd.c agent/tpm2/tpm2_util.c agent/tpm2/tpm2_output.c agent/tpm2/tpm2_getcap.c agent/tpm2/tpm2_pcrread.c agent/tpm2/tpm2_nvreadpublic.c agent/tpm2/tpm2_createprimary.c agent/orom/orom_pull_cmd_common.c agent/efi/efi_pull_orom_cmd.c agent/efi/efi_dump_vars_cmd.c agent/bios/bios_pull_orom_cmd.c \
	  agent/uboot/audit-rules/uboot_validate_crc32_rule.c \
	  agent/uboot/audit-rules/uboot_validate_cmdline_init_writeability_rule.c \
	  agent/uboot/audit-rules/uboot_validate_env_security_rule.c \
	  agent/uboot/audit-rules/uboot_validate_env_writeability_rule.c \
	  agent/uboot/audit-rules/uboot_validate_secureboot_rule.c \
	  agent/transfer/transfer_cmd.c \
	  agent/arch/arch_cmd.c \
	  agent/net/api_key.c \
	  agent/net/ws_client.c \
	  $(LIBCSV_SRC) $(GENERATED_CA_SRC)

.PHONY: all env image static test build-unit-agent-c test-unit-agent-c clean check-autoconf check-autoreconf check-zig check-llvm-objcopy

check-zig:
	@if [ "$(NEEDS_ZIG)" != "1" ]; then \
		exit 0; \
	fi; \
	if [ -x "$(ZIG_BIN)" ]; then \
		exit 0; \
	fi; \
	if [ -z "$(ZIG_HOST_TRIPLE)" ] || [ -z "$(ZIG_DOWNLOAD_HOST)" ]; then \
		echo "error: zig not found on PATH and automatic Zig download is unsupported on host $(HOST_OS)/$(HOST_ARCH)"; \
		exit 1; \
	fi; \
	archive_name="zig-$(ZIG_DOWNLOAD_HOST)-$(ZIG_VERSION).tar.xz"; \
	tmp_dir="$(abspath $(TOOLS_CACHE_DIR))/zig/tmp"; \
	archive_path="$$tmp_dir/$$archive_name"; \
	extract_dir="$$tmp_dir/extract-$(ZIG_HOST_TRIPLE)-$(ZIG_VERSION)"; \
	extracted_root="$$extract_dir/zig-$(ZIG_DOWNLOAD_HOST)-$(ZIG_VERSION)"; \
	archive_url="https://ziglang.org/download/$(ZIG_VERSION)/$$archive_name"; \
	echo "zig not found on PATH; downloading Zig $(ZIG_VERSION) for $(ZIG_HOST_TRIPLE)"; \
	mkdir -p "$$tmp_dir"; \
	rm -rf "$$extract_dir"; \
	if command -v curl >/dev/null 2>&1; then \
		curl -fL "$$archive_url" -o "$$archive_path"; \
	elif command -v wget >/dev/null 2>&1; then \
		wget -O "$$archive_path" "$$archive_url"; \
	else \
		echo "error: need curl or wget to download $$archive_url"; \
		exit 1; \
	fi; \
	if ! command -v tar >/dev/null 2>&1; then \
		echo "error: tar is required to extract $$archive_name"; \
		exit 1; \
	fi; \
	mkdir -p "$$extract_dir"; \
	tar -xJf "$$archive_path" -C "$$extract_dir"; \
	if [ ! -x "$$extracted_root/zig" ]; then \
		echo "error: downloaded Zig archive did not contain expected binary: $$extracted_root/zig"; \
		exit 1; \
	fi; \
	mkdir -p "$(dir $(ZIG_CACHE_DIR))"; \
	rm -rf "$(ZIG_CACHE_DIR)"; \
	mv "$$extracted_root" "$(ZIG_CACHE_DIR)"; \
	rm -rf "$$extract_dir"; \
	rm -f "$$archive_path"

check-llvm-objcopy:
	@if [ "$(NEEDS_ZIG)" != "1" ]; then \
		exit 0; \
	fi; \
	if command -v "$(LLVM_OBJCOPY_BIN)" >/dev/null 2>&1; then \
		exit 0; \
	fi; \
	echo "llvm-objcopy not found; attempting to install it"; \
	manager=""; \
	package=""; \
	if command -v apt-get >/dev/null 2>&1; then \
		manager="apt-get"; \
		package="llvm"; \
	elif command -v dnf >/dev/null 2>&1; then \
		manager="dnf"; \
		package="llvm"; \
	elif command -v yum >/dev/null 2>&1; then \
		manager="yum"; \
		package="llvm"; \
	elif command -v zypper >/dev/null 2>&1; then \
		manager="zypper"; \
		package="llvm"; \
	elif command -v pacman >/dev/null 2>&1; then \
		manager="pacman"; \
		package="llvm"; \
	elif command -v apk >/dev/null 2>&1; then \
		manager="apk"; \
		package="llvm"; \
	else \
		echo "error: llvm-objcopy is required for Zig cross-builds and no supported package manager was detected"; \
		exit 1; \
	fi; \
	runner=""; \
	if [ "$$(id -u)" -eq 0 ]; then \
		runner=""; \
	elif command -v sudo >/dev/null 2>&1; then \
		runner="sudo"; \
	elif command -v doas >/dev/null 2>&1; then \
		runner="doas"; \
	else \
		echo "error: need root privileges (or sudo/doas) to install $$package"; \
		exit 1; \
	fi; \
	case "$$manager" in \
		apt-get) $${runner:+$$runner }apt-get update && $${runner:+$$runner }apt-get install -y "$$package" ;; \
		dnf) $${runner:+$$runner }dnf install -y "$$package" ;; \
		yum) $${runner:+$$runner }yum install -y "$$package" ;; \
		zypper) $${runner:+$$runner }zypper --non-interactive install "$$package" ;; \
		pacman) $${runner:+$$runner }pacman -Sy --noconfirm "$$package" ;; \
		apk) $${runner:+$$runner }apk add --no-cache "$$package" ;; \
		esac; \
	if ! command -v "$(LLVM_OBJCOPY_BIN)" >/dev/null 2>&1; then \
		echo "error: installed $$package but llvm-objcopy is still unavailable"; \
		exit 1; \
	fi

check-autoconf:
	@command -v $(AUTOCONF) >/dev/null 2>&1 || { \
		echo "error: autoconf is required for some third_party dependency builds."; \
		echo "hint: install autoconf and rerun make."; \
		exit 1; \
	}

check-autoreconf:
	@command -v autoreconf >/dev/null 2>&1 || { \
		echo "error: autoreconf is required to regenerate third_party/wolfssl configure scripts when sources are newer than generated files."; \
		echo "hint: install automake/libtool-bin/autoconf on Debian-based systems (or the equivalent libtool package on your distro) and rerun make."; \
		exit 1; \
	}

all: $(TARGET)

env: $(TARGET)

image: $(TARGET)

$(TARGET): | check-zig

$(JSONC_LIB):
	rm -rf $(JSONC_BUILD)
	cmake -S $(JSONC_DIR) -B $(JSONC_BUILD) $(JSONC_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_APPS=OFF -DDISABLE_EXTRA_LIBS=ON -DENABLE_RDRAND=OFF -DENABLE_THREADING=OFF -DDISABLE_JSON_POINTER=ON -DDISABLE_THREAD_LOCAL_STORAGE=ON
	cmake --build $(JSONC_BUILD) --parallel $(JOBS) --target json-c

$(LIBUBOOTENV_LIB): $(ZLIB_LIB)
	rm -rf $(LIBUBOOTENV_BUILD)
	cmake -S $(LIBUBOOTENV_DIR) -B $(LIBUBOOTENV_BUILD) $(CMAKE_CC_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_DOC=OFF -DNO_YML_SUPPORT=ON -DCMAKE_C_FLAGS="$(LIBUBOOTENV_EXTRA_CFLAGS)"
	cmake --build $(LIBUBOOTENV_BUILD) --parallel $(JOBS) --target ubootenv_static

$(LIBEFIVAR_BUILD_STAMP):
	-$(MAKE) -C $(LIBEFIVAR_DIR)/src TOPDIR='$(abspath $(LIBEFIVAR_DIR))' clean >/dev/null 2>&1 || true
	$(MAKE) -C $(LIBEFIVAR_DIR)/src TOPDIR='$(abspath $(LIBEFIVAR_DIR))' libefivar.a CC='$(CC)' HOSTCC='cc' HOSTCCLD='cc' AR='ar' RANLIB='ranlib' CPPFLAGS='-I$(abspath $(LIBEFIVAR_DIR))/src/include' HOST_CFLAGS='$(LIBEFIVAR_HOST_CFLAGS)' HOST_CPPFLAGS='$(LIBEFIVAR_HOST_CPPFLAGS)' HOST_LDFLAGS='$(LIBEFIVAR_HOST_LDFLAGS)' HOST_CCLDFLAGS='$(LIBEFIVAR_HOST_LDFLAGS)'
	test -f $(LIBEFIVAR_LIB)
	touch $@

$(ZLIB_LIB):
	rm -rf $(ZLIB_BUILD)
	cmake -S $(ZLIB_DIR) -B $(ZLIB_BUILD) $(ZLIB_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DZLIB_BUILD_SHARED=OFF -DZLIB_BUILD_STATIC=ON -DZLIB_BUILD_TESTING=OFF -DZLIB_INSTALL=OFF
	cmake --build $(ZLIB_BUILD) --parallel $(JOBS) --target zlibstatic

$(CURL_LIB): $(CURL_SSL_DEP) Makefile
	rm -f $(CURL_BUILD)/CMakeCache.txt
	rm -f $(CURL_LIB)
	cmake -S $(CURL_DIR) -B $(CURL_BUILD) $(CURL_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DBUILD_TESTING=OFF $(CURL_CMAKE_SSL_ARGS) -DCURL_ZLIB=OFF -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DENABLE_ARES=OFF -DENABLE_THREADED_RESOLVER=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DUSE_ECH=OFF -DUSE_NTLM=OFF -DUSE_OPENLDAP=OFF -DUSE_LIBRTMP=OFF -DCURL_DISABLE_WEBSOCKETS=OFF -DCURL_DISABLE_NETRC=ON -DCURL_DISABLE_DICT=ON -DCURL_DISABLE_FILE=ON -DCURL_DISABLE_FTP=ON -DCURL_DISABLE_GOPHER=ON -DCURL_DISABLE_IMAP=ON -DCURL_DISABLE_IPFS=ON -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON -DCURL_DISABLE_MQTT=ON -DCURL_DISABLE_POP3=ON -DCURL_DISABLE_RTSP=ON -DCURL_DISABLE_SMB=ON -DCURL_DISABLE_SMTP=ON -DCURL_DISABLE_TELNET=ON -DCURL_DISABLE_TFTP=ON -DCURL_DISABLE_PROXY=ON -DCURL_DISABLE_ALTSVC=ON -DCURL_DISABLE_HSTS=ON -DCURL_DISABLE_MIME=ON -DCURL_DISABLE_PROGRESS_METER=ON -DCURL_DISABLE_GETOPTIONS=ON -DCURL_DISABLE_SOCKETPAIR=ON -DCURL_DISABLE_BINDLOCAL=ON -DCURL_DISABLE_DOH=ON -DCURL_DISABLE_HTTP_AUTH=ON -DCURL_DISABLE_AWS=ON -DCURL_DISABLE_SHUFFLE_DNS=ON -DCURL_DISABLE_HEADERS_API=ON -DCURL_DISABLE_LIBCURL_OPTION=ON -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON -DCURL_DISABLE_PARSEDATE=ON -DCURL_DISABLE_SRP=ON
	cmake --build $(CURL_BUILD) --parallel $(JOBS) --target libcurl_static

$(LIBSSH_LIB): $(OPENSSL_SSL_LIB) $(ZLIB_LIB)
	rm -rf $(LIBSSH_BUILD)
	cmake -S $(LIBSSH_DIR) -B $(LIBSSH_BUILD) $(LIBSSH_CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIB=ON -DWITH_EXAMPLES=OFF -DUNIT_TESTING=OFF -DCLIENT_TESTING=OFF -DSERVER_TESTING=OFF -DWITH_SERVER=OFF -DWITH_GSSAPI=OFF -DWITH_NACL=OFF -DWITH_ZLIB=ON -DZLIB_INCLUDE_DIR="$(abspath $(ZLIB_DIR))" -DZLIB_LIBRARY="$(abspath $(ZLIB_LIB))" -DOPENSSL_ROOT_DIR="$(abspath $(OPENSSL_INSTALL))" -DOPENSSL_INCLUDE_DIR="$(abspath $(OPENSSL_INSTALL))/include" -DOPENSSL_CRYPTO_LIBRARY="$(abspath $(OPENSSL_LIB))" -DWITH_PCAP=OFF -DWITH_DEBUG_CALLTRACE=OFF
	cmake --build $(LIBSSH_BUILD) --parallel $(JOBS) --target ssh-static

$(TPM2_TSS_BUILD_STAMP): $(OPENSSL_SSL_LIB)
	if [ ! -x "$(TPM2_TSS_DIR)/configure" ] || [ ! -f "$(TPM2_TSS_DIR)/src_vars.mk" ] || [ ! -f "$(TPM2_TSS_DIR)/aclocal.m4" ] || [ ! -f "$(TPM2_TSS_DIR)/config.guess" ] || [ ! -f "$(TPM2_TSS_DIR)/config.sub" ] || [ ! -f "$(TPM2_TSS_DIR)/install-sh" ] || grep -qE '\b(AX_[A-Z0-9_]+|DX_[A-Z0-9_]+)\b' "$(TPM2_TSS_DIR)/configure"; then \
		$(MAKE) check-autoreconf; \
		mkdir -p "$(TPM2_TSS_DIR)/m4"; \
		cp build_support/tpm2-tss/ela_fallbacks.m4 "$(TPM2_TSS_DIR)/m4/ela_fallbacks.m4"; \
		cp build_support/tpm2-tss/aminclude_static.am "$(TPM2_TSS_DIR)/aminclude_static.am"; \
		cd $(TPM2_TSS_DIR) && \
			AUTORECONF='autoreconf -I m4' \
			ACLOCAL='aclocal -I m4' \
			ACLOCAL_PATH="$(abspath $(TPM2_TSS_DIR))/m4$${ACLOCAL_PATH:+:$${ACLOCAL_PATH}}" \
			./bootstrap; \
	fi
	rm -rf $(TPM2_TSS_BUILD)
	mkdir -p $(TPM2_TSS_BUILD)
	cd $(TPM2_TSS_BUILD) && \
		ZIG_GLOBAL_CACHE_DIR='$(TPM2_TSS_ZIG_GLOBAL_CACHE)' \
		ZIG_LOCAL_CACHE_DIR='$(abspath $(TPM2_TSS_BUILD))/.zig-cache' \
		ac_cv_path_lt_DD='/usr/bin/dd' \
		lt_cv_truncate_bin='sed -e 4q' \
		CC='$(CC)' \
		AR='ar' \
		RANLIB='ranlib' \
		CFLAGS='$(TPM2_TSS_BUILD_CFLAGS)' \
		CPPFLAGS='-I$(abspath $(OPENSSL_INSTALL))/include' \
		LDFLAGS='-L$(abspath $(OPENSSL_INSTALL))/lib' \
		CRYPTO_CFLAGS='-I$(abspath $(OPENSSL_INSTALL))/include' \
		CRYPTO_LIBS='-L$(abspath $(OPENSSL_INSTALL))/lib -lcrypto' \
		$(abspath $(TPM2_TSS_DIR))/configure \
			$(TPM2_TSS_CONFIGURE_BUILD_ARG) \
			$(TPM2_TSS_CONFIGURE_HOST_ARG) \
			--disable-shared \
			--enable-static \
			--disable-fapi \
			--disable-policy \
			--disable-tcti-mssim \
			--disable-tcti-swtpm \
			--disable-tcti-pcap \
			--disable-tcti-null \
			--disable-tcti-libtpms \
			--disable-tcti-cmd \
			--disable-tcti-spi-helper \
			--disable-tcti-spi-ltt2go \
			--disable-tcti-spidev \
			--disable-tcti-spi-ftdi \
			--disable-tcti-i2c-helper \
			--disable-tcti-i2c-ftdi \
			--disable-unit \
			--disable-integration \
			--enable-nodl \
			--disable-log-file \
			--with-maxloglevel=error
	ZIG_GLOBAL_CACHE_DIR='$(TPM2_TSS_ZIG_GLOBAL_CACHE)' \
	ZIG_LOCAL_CACHE_DIR='$(abspath $(TPM2_TSS_BUILD))/.zig-cache' \
	$(MAKE) -C $(TPM2_TSS_BUILD) -j$(JOBS)
	test -f $(TPM2_TSS_ESYS_LIB)
	test -f $(TPM2_TSS_SYS_LIB)
	test -f $(TPM2_TSS_MU_LIB)
	test -f $(TPM2_TSS_RC_LIB)
	test -f $(TPM2_TSS_TCTI_DEVICE_LIB)
	touch $@

$(OPENSSL_LIB): $(OPENSSL_SSL_LIB)

$(WOLFSSL_LIB): check-autoconf
	mkdir -p $(WOLFSSL_BUILD)
	if [ ! -x "$(WOLFSSL_DIR)/configure" ] \
		|| [ "$(WOLFSSL_DIR)/configure.ac" -nt "$(WOLFSSL_DIR)/configure" ] \
		|| [ "$(WOLFSSL_DIR)/aclocal.m4" -nt "$(WOLFSSL_DIR)/configure" ] \
		|| grep -qE '^[[:space:]]*(LT_PREREQ|LT_INIT)\(' "$(WOLFSSL_DIR)/configure"; then \
		$(MAKE) check-autoreconf; \
		cd $(WOLFSSL_DIR) && \
			ACLOCAL='aclocal -I m4' \
			ACLOCAL_PATH="$(abspath $(WOLFSSL_DIR))/m4$${ACLOCAL_PATH:+:$${ACLOCAL_PATH}}" \
			WARNINGS=all \
			sh ./autogen.sh; \
	fi
	cd $(WOLFSSL_BUILD) && $(abspath $(WOLFSSL_DIR))/configure \
		CC="$(CC)" \
		$(if $(WOLFSSL_CONFIGURE_CFLAGS),CFLAGS="$(WOLFSSL_CONFIGURE_CFLAGS)") \
		$(WOLFSSL_CONFIGURE_HOST_ARG) \
		$(WOLFSSL_EXTRA_CONFIGURE_FLAGS) \
		$(WOLFSSL_LIBRARY_CONFIGURE_FLAGS) \
		--enable-opensslextra \
		--disable-benchmark --disable-examples \
		--disable-crypttests --disable-dtls --disable-oldtls --disable-tls13 \
		--enable-sni \
		--disable-arc4 --disable-des3 --disable-anon \
		--disable-psk --disable-srp --disable-srtp --disable-scrypt \
		--disable-aria --disable-camellia --disable-blake2 \
		--disable-crl \
		--prefix="$(abspath $(WOLFSSL_BUILD))/install" \
		$(WOLFSSL_CONFIGURE_SIZEOF_ARGS)
	$(MAKE) -C $(WOLFSSL_BUILD) -j$(JOBS)
	$(MAKE) -C $(WOLFSSL_BUILD) install

$(OPENSSL_SSL_LIB):
	mkdir -p $(OPENSSL_BUILD)
	cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	# Use no-asm so cross builds (e.g. zig cc -target arm-*) don't pick host x86 asm paths.
	cd $(OPENSSL_DIR) && CC="$(CC)" ./Configure $(OPENSSL_CONFIGURE_TARGET) no-asm no-shared no-module no-threads no-tests no-docs $(OPENSSL_DISABLE_FEATURES) $(OPENSSL_EXTRA_CONFIGURE_FLAGS) --prefix="$(abspath $(OPENSSL_INSTALL))" --openssldir="$(abspath $(OPENSSL_INSTALL))/ssl" --libdir=lib
	$(MAKE) -C $(OPENSSL_DIR) -j$(JOBS) build_generated
	$(MAKE) -C $(OPENSSL_DIR) -j$(JOBS) build_libs
	mkdir -p "$(OPENSSL_INSTALL)/include" "$(OPENSSL_INSTALL)/lib" "$(OPENSSL_CMAKE_DIR)"
	rm -rf "$(OPENSSL_INSTALL)/include/openssl"
	cp -a "$(OPENSSL_DIR)/include/openssl" "$(OPENSSL_INSTALL)/include/"
	cp "$(OPENSSL_DIR)/libssl.a" "$(OPENSSL_SSL_LIB)"
	cp "$(OPENSSL_DIR)/libcrypto.a" "$(OPENSSL_LIB)"
	cp "$(OPENSSL_DIR)/exporters/OpenSSLConfig.cmake" "$(OPENSSL_CMAKE_DIR)/OpenSSLConfig.cmake"
	cp "$(OPENSSL_DIR)/exporters/OpenSSLConfigVersion.cmake" "$(OPENSSL_CMAKE_DIR)/OpenSSLConfigVersion.cmake"

$(GENERATED_DIR):
	mkdir -p $(GENERATED_DIR)

ifeq ($(CA_BUNDLE_PEM),$(DEFAULT_CA_BUNDLE_PEM))
$(DEFAULT_CA_BUNDLE_PEM): | $(GENERATED_DIR)
	curl -fsSL "$(CA_BUNDLE_URL)" -o "$@"
endif

$(GENERATED_CA_SRC): tools/embed_ca_bundle.py $(CA_BUNDLE_PEM)
	python3 tools/embed_ca_bundle.py --input "$(CA_BUNDLE_PEM)" --output "$@"

$(LIBEFIVAR_LINK_LIB): $(LIBEFIVAR_BUILD_STAMP) | $(GENERATED_DIR) check-llvm-objcopy
	rm -rf "$(LIBEFIVAR_REPACK_DIR)"
	mkdir -p "$(LIBEFIVAR_REPACK_DIR)"
	cd "$(LIBEFIVAR_REPACK_DIR)" && ar x "$(abspath $(LIBEFIVAR_LIB))"
	for obj in "$(LIBEFIVAR_REPACK_DIR)"/*.o; do \
		$(OBJCOPY) --redefine-sym crc32=efivar_crc32 "$$obj"; \
	done
	rm -f "$@"
	ar rcs "$@" "$(LIBEFIVAR_REPACK_DIR)"/*.o

$(NCURSES_BUILD_STAMP):
	cd $(NCURSES_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	cd $(NCURSES_DIR) && ./configure --without-shared --without-cxx --without-cxx-binding --without-ada --without-tests --without-progs --without-manpages --with-normal --with-termlib --disable-home-terminfo CC='$(CC)' CFLAGS='$(CFLAGS)'
	$(MAKE) -C $(NCURSES_DIR) -j$(JOBS) libs
	touch $@

$(READLINE_BUILD_STAMP):
	cd $(READLINE_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	cd $(READLINE_DIR) && bash_cv_termcap_lib=libtermcap ac_cv_type_signal=void bash_cv_void_sighandler=yes ./configure --disable-shared --enable-static CC='$(CC) -std=gnu89' CFLAGS='$(READLINE_BUILD_CFLAGS)' LDFLAGS='-L$(abspath $(NCURSES_LIB_DIR))'
	$(MAKE) -C $(READLINE_DIR) -j$(JOBS) libreadline.a libhistory.a
	touch $@

TARGET_DEPS := $(SRC) $(ZLIB_LIB) $(LIBUBOOTENV_LIB) $(LIBEFIVAR_BUILD_STAMP) $(LIBEFIVAR_LINK_LIB) $(JSONC_LIB) $(CURL_LIB) $(LIBSSH_LIB) $(OPENSSL_SSL_LIB) $(OPENSSL_LIB) $(READLINE_DEPS)
TARGET_LIBS := $(LIBUBOOTENV_LIB) $(LIBEFIVAR_LINK_LIB) $(JSONC_LIB) $(CURL_LIB) $(LIBSSH_LIB) $(ZLIB_LIB)
ifeq ($(ELA_ENABLE_TPM2),1)
TARGET_DEPS += $(TPM2_TSS_BUILD_STAMP)
TARGET_LIBS += $(TPM2_TSS_ESYS_LIB) $(TPM2_TSS_SYS_LIB) $(TPM2_TSS_TCTI_DEVICE_LIB) $(TPM2_TSS_MU_LIB) $(TPM2_TSS_RC_LIB)
endif
TARGET_LIBS += $(OPENSSL_SSL_LIB) $(OPENSSL_LIB)
ifeq ($(ELA_ENABLE_WOLFSSL),1)
TARGET_DEPS += $(WOLFSSL_LIB)
TARGET_LIBS += $(WOLFSSL_LIB)
endif

$(TARGET_DEPS): | check-zig

$(TARGET): $(TARGET_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(TARGET_LIBS) $(LDFLAGS) $(LDLIBS)

static: all

$(AGENT_UNIT_TEST_BIN): $(AGENT_UNIT_TEST_SRC) $(AGENT_UNIT_TEST_DEPS) $(JSONC_LIB) | $(GENERATED_DIR)
	$(UNIT_TEST_CC) $(UNIT_TEST_CFLAGS) -I. -Iagent -Ithird_party -Ithird_party/libcsv -I$(JSONC_DIR) -I$(JSONC_BUILD) \
		-o $@ \
		$(AGENT_UNIT_TEST_SRC) \
		third_party/libcsv/libcsv.c \
		agent/util/str_util.c \
		agent/util/isa_util.c \
			agent/util/crc32_util.c \
			agent/util/http_uri_util.c \
			agent/util/command_parse_util.c \
			agent/util/record_formatter.c \
			agent/util/list_files_filter_util.c \
			agent/util/lifecycle_formatter.c \
			agent/util/interactive_parse_util.c \
			agent/util/file_scan_formatter.c \
			agent/util/tpm2_pcr_parse_util.c \
			agent/util/remote_copy_util.c \
			agent/util/orom_util.c \
			agent/util/http_protocol_util.c \
			agent/util/command_io_util.c \
			agent/util/ssh_parse_util.c \
			agent/util/tpm2_output_format_util.c \
			agent/util/tpm2_command_util.c \
			agent/util/transfer_parse_util.c \
			agent/linux/linux_dmesg_util.c \
			agent/linux/remote_copy_cmd_util.c \
			agent/net/ela_conf_util.c \
			agent/net/ws_url_util.c \
			agent/net/ws_connect_util.c \
			agent/net/ws_interactive_util.c \
			agent/net/tcp_parse_util.c \
			agent/net/tcp_runtime_util.c \
			agent/net/api_key_util.c \
			agent/net/ws_frame_util.c \
			agent/net/ws_session_util.c \
			agent/net/http_ws_policy_util.c \
			agent/net/http_client_parse_util.c \
			agent/net/http_client_body_util.c \
			agent/net/http_client_protocol_util.c \
			agent/net/http_client_runtime_util.c \
			agent/net/ws_recv_util.c \
			agent/uboot/env/uboot_env_format_util.c \
			agent/uboot/env/uboot_env_record_util.c \
			agent/uboot/env/uboot_env_util.c \
			agent/uboot/env/uboot_env_scan_util.c \
			agent/uboot/audit-rules/uboot_audit_util.c \
			agent/uboot/uboot_security_audit_util.c \
			agent/uboot/image/uboot_command_extract_util.c \
			agent/uboot/image/uboot_image_format_util.c \
			agent/uboot/image/uboot_image_record_util.c \
			agent/linux/linux_execute_command_util.c \
			agent/shell/script_exec_util.c \
			agent/shell/interactive_util.c \
			$(JSONC_LIB) \
			$(UNIT_TEST_LDFLAGS)

build-unit-agent-c: $(AGENT_UNIT_TEST_BIN)

test-unit-agent-c: build-unit-agent-c
	./$(AGENT_UNIT_TEST_BIN)

coverage-agent-c:
	rm -rf $(COVERAGE_DIR)
	find . -name '*.gcda' -delete
	find . -name '*.gcno' -delete
	$(MAKE) clean
	$(MAKE) all build-unit-agent-c \
		CC="$(COVERAGE_CC)" \
		HOSTCC="$(COVERAGE_CC)" \
		UNIT_TEST_CC="$(COVERAGE_CC)" \
		CFLAGS_APPEND="$(COVERAGE_EXTRA_CFLAGS)" \
		HOSTCFLAGS_APPEND="$(COVERAGE_EXTRA_HOSTCFLAGS)" \
		UNIT_TEST_CFLAGS_APPEND="$(COVERAGE_EXTRA_UNIT_TEST_CFLAGS)" \
		LDFLAGS="$(COVERAGE_EXTRA_LDFLAGS)" \
		UNIT_TEST_LDFLAGS="$(COVERAGE_EXTRA_LDFLAGS)" \
		ELA_USE_READLINE=0
	./$(AGENT_UNIT_TEST_BIN)
	BIN="./$(TARGET)" bash tests/agent/shell/test_all.sh
	mkdir -p $(COVERAGE_DIR)
	lcov --capture --directory . --output-file $(AGENT_C_COVERAGE_INFO)
	lcov --remove $(AGENT_C_COVERAGE_INFO) \
		'/usr/*' \
		'third_party/*' \
		'tests/*' \
		'generated/*' \
		'compat/*' \
		--output-file $(AGENT_C_COVERAGE_INFO) || \
		{ _lcov_rc=$$?; test "$$_lcov_rc" -eq 25; }

coverage-agent-c-html: coverage-agent-c
	genhtml $(AGENT_C_COVERAGE_INFO) --output-directory $(AGENT_C_COVERAGE_HTML)
test:
	$(MAKE) test-unit-agent-c
	bash tests/agent/shell/test_all.sh

clean:
	rm -f $(TARGET)
	rm -rf $(GENERATED_DIR)
	rm -f $(LIBEFIVAR_DIR)/.ela-build-*
	rm -f $(NCURSES_DIR)/.ela-build-*
	rm -f $(READLINE_DIR)/.ela-build-*
	rm -f generated/libefivar-link-*.a
	rm -rf generated/libefivar-repack-*
	rm -rf $(JSONC_DIR)/build*
	rm -rf $(LIBUBOOTENV_DIR)/build*
	-$(MAKE) -C $(LIBEFIVAR_DIR)/src TOPDIR='$(abspath $(LIBEFIVAR_DIR))' clean >/dev/null 2>&1 || true
	rm -f $(LIBEFIVAR_BUILD_STAMP)
	rm -rf $(ZLIB_DIR)/build*
	rm -rf $(CURL_DIR)/build*
	rm -rf $(LIBSSH_DIR)/build*
	rm -rf $(TPM2_TSS_DIR)/build*
	rm -rf $(WOLFSSL_DIR)/build*
	-cd $(OPENSSL_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -rf $(OPENSSL_BUILD)
	-cd $(NCURSES_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -f $(NCURSES_BUILD_STAMP)
	-cd $(READLINE_DIR) && $(MAKE) distclean >/dev/null 2>&1 || true
	rm -f $(READLINE_BUILD_STAMP)
	-git submodule foreach --recursive 'git clean -xfd >/dev/null 2>&1 || true'
	-git submodule foreach --recursive 'git reset --hard >/dev/null 2>&1 || true'
