BUILD := build
INCLUDE := include
SRC := src
TEST := test
EXE := hh

CFLAGS += -Wall -Wextra -Wpedantic -Iinclude -g
LDLIBS += -ls2n -lcrypto -pthread

SRCS := $(shell find $(SRC) -name "*.c")
OBJS := $(addprefix $(BUILD)/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
TESTS := $(shell find $(TEST) -name "test_*.py")

.PHONY: all clean run test valgrind stress

all: $(BUILD)/$(EXE)

clean:
	rm -rvf $(BUILD)

run: $(BUILD)/$(EXE)
	@echo "------------"
	@./$(BUILD)/$(EXE)

valgrind: $(EXE)
	@valgrind ./$(EXE)

stress: $(BUILD)/$(EXE)
	@./$(BUILD)/$(EXE) > $(BUILD)/output.log &
	@sleep 0.3
	tcpkali -c 200 -m "Some message" localhost:8000 --latency-connect --latency-first-byte -T 20
	@killall --signal SIGINT -w "$(EXE)"
	@echo "----------- Server output -----------"
	@cat $(BUILD)/output.log

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
	$(CC) $(CFLAGS) -c $< -o $@
