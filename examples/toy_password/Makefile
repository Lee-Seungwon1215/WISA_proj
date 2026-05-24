CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-inline -fno-omit-frame-pointer
CPPFLAGS = -Iinclude

BUILD = build

.PHONY: all clean

all: $(BUILD)/harness_bad $(BUILD)/harness_safe

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/harness_bad: harness/harness_bad.c src/bad_compare.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

$(BUILD)/harness_safe: harness/harness_safe.c src/safe_compare.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD)
