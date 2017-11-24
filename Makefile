BUILD := build
INCLUDE := include
SRC := src
TEST := test
EXE := hh

CFLAGS += -Wall -Wextra -std=gnu11 -Iinclude -g -DWORKER_THREADS=3
LDLIBS += -ls2n -lcrypto -pthread

SRCS := $(shell find $(SRC) -name "*.c")
OBJS := $(addprefix $(BUILD)/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
TESTS := $(shell find $(TEST) -name "test_*.py")
DEPFILES := $(patsubst %.o,%.d,$(OBJS))

.PHONY: all clean run test valgrind rebuild cloc hexdump

ifeq ($(HH_DEBUG),1)
  CFLAGS += -O0 -fsanitize=address,undefined
else
  CFLAGS += -O2 -DNDEBUG
endif

all: $(BUILD)/$(EXE)

clean:
	rm -rvf $(BUILD)

rebuild: clean all

cloc:
	@cloc . --not-match-d="build"

hexdump: $(BUILD)/$(EXE)
	@./$(BUILD)/$(EXE) 2>&1 >/dev/null | hexdump -e '1/1 " %02X"' -C

run: $(BUILD)/$(EXE)
	@echo "------------"
	@./$(BUILD)/$(EXE) 8000

valgrind: $(BUILD)/$(EXE)
	@valgrind ./$(BUILD)/$(EXE)

test: $(BUILD)/$(EXE)
	@./$(BUILD)/$(EXE) > $(BUILD)/output.log &
	@sleep 0.3
	@for TEST in $(TESTS); do python3 $$TEST; done
	@killall --signal SIGINT -w "$(EXE)"
	@echo "----------- Server output -----------"
	@cat $(BUILD)/output.log

$(BUILD)/$(EXE): $(BUILD) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ -L$(BUILD) $(LDLIBS)

$(BUILD):
	mkdir $@

$(BUILD)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -MD

-include $(DEPFILES)
