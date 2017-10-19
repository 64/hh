BUILD := build
INCLUDE := include
SRC := src
TEST := test

CFLAGS += -Wall -Wextra -Wpedantic -fPIC -Iinclude
LDLIBS += -ls2n -luv

SRCS := $(shell find $(SRC) -name "*.c")
OBJS := $(addprefix $(BUILD)/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
TESTS := $(shell find $(TEST) -name "test_*.py")

.PHONY: all clean run test

all: $(BUILD)/libhh.a $(BUILD)/libhh.so

clean:
	rm -rvf $(BUILD)

run: all
	@echo "------------"
	@python3 $(TEST)/run.py

test: all
	@for TEST in $(TESTS); do python3 $$TEST; done

$(BUILD)/libhh.a: $(BUILD) $(OBJS)
	$(AR) -rcs $(BUILD)/libhh.a $(OBJS)

$(BUILD)/libhh.so: $(BUILD) $(OBJS)
	$(CC) -shared $(LDFLAGS) $(LDLIBS) -o $@ $(OBJS)

$(BUILD):
	mkdir $@

$(BUILD)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@
