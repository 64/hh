BUILD := build
INCLUDE := include
SRC := src
TEST := test

CFLAGS += -Wall -Wextra -Wpedantic -Og
LDFLAGS += -L~/deps/s2n/lib -ls2n

SRCS := $(shell find $(SRC) -name "*.c")
OBJS := $(addprefix $(BUILD)/,$(notdir $(patsubst %.c,%.o,$(SRCS))))

.PHONY: all clean

all: $(BUILD)/libhh.a

clean:
	rm -rvf $(BUILD)/

$(BUILD)/libhh.a: $(BUILD) $(OBJS)
	$(AR) $(LDFLAGS) -rcs $(BUILD)/libhh.a -o $(OBJS)

$(BUILD):
	mkdir $@

$(BUILD)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@
