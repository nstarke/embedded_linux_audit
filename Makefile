CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS  ?=

LIBCSV_DIR    := third_party/libcsv
LIBCSV_SRC    := $(LIBCSV_DIR)/libcsv.c
LIBCSV_CFLAGS := -I$(LIBCSV_DIR)
JSONC_DIR     := third_party/json-c
JSONC_BUILD   := $(JSONC_DIR)/build-$(notdir $(CC))
JSONC_LIB     := $(JSONC_BUILD)/libjson-c.a
JSONC_CFLAGS  := -I$(JSONC_DIR) -I$(JSONC_BUILD)

CFLAGS += $(LIBCSV_CFLAGS)
CFLAGS += $(JSONC_CFLAGS)

TARGET := uboot_audit
SRC    := uboot_audit.c uboot_env_scan.c uboot_image_scan.c uboot_scan.c $(LIBCSV_SRC)

.PHONY: all env image static clean

all: $(TARGET)

env: $(TARGET)

image: $(TARGET)

$(JSONC_LIB):
	cmake -S $(JSONC_DIR) -B $(JSONC_BUILD) -DCMAKE_C_COMPILER=$(CC) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_APPS=OFF
	cmake --build $(JSONC_BUILD) --target json-c

$(TARGET): $(SRC) $(JSONC_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(JSONC_LIB) $(LDFLAGS) $(LDLIBS)

static: LDFLAGS += -static
static: all

clean:
	rm -f $(TARGET)
	rm -rf $(JSONC_DIR)/build*