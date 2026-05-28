ifndef TARGET_COMPILE
    $(info TARGET_COMPILE not set, trying auto-detection...)
    TARGET_COMPILE := $(shell \
        for pfx in aarch64-none-elf- aarch64-elf-; do \
            if command -v $${pfx}gcc >/dev/null 2>&1; then \
                echo "$${pfx}"; exit 0; \
            fi; \
        done)
    ifeq ($(TARGET_COMPILE),)
        $(error TARGET_COMPILE not set and no cross-compiler found (tried aarch64-none-elf-, aarch64-elf-))
    else
        $(info Auto-detected TARGET_COMPILE=$(TARGET_COMPILE))
    endif
endif

ifndef KP_DIR
    KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
INCLUDE_FLAGS += -I.

CFLAGS += -std=gnu11 -O2

SRCS += ./kpm_frida.c
SRCS += ./debugger_hide.c
SRCS += ./frida_hide.c
SRCS += ./openat_hide.c
SRCS += ./net_hide.c
SRCS += ./mem_hide.c

OBJS := $(SRCS:.c=.o)

all: KPM_FRIDA.kpm

push: KPM_FRIDA.kpm
	adb push KPM_FRIDA.kpm /sdcard/Download/

KPM_FRIDA.kpm: ${OBJS}
	${CC} -r -o $@ $^
	find . -name "*.o" | xargs rm -f

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean all push
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
