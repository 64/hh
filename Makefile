BUILD := build
INCLUDE := include
SRC := src
TEST := test
TEST_SERVER := test_server

CFLAGS += -Wall -Wextra -Wpedantic -Iinclude -g
LDLIBS += -ls2n -lcrypto -pthread

SRCS := $(shell find $(SRC) -name "*.c")
OBJS := $(addprefix $(BUILD)/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
TESTS := $(shell find $(TEST) -name "test_*.py")

.PHONY: all clean run test valgrind stress

all: $(BUILD)/libhh.a $(BUILD)/libhh.so

clean:
	rm -rvf $(BUILD)

run: $(BUILD)/$(TEST_SERVER)
	@echo "------------"
	@./$(BUILD)/$(TEST_SERVER)

valgrind: $(BUILD)/$(TEST_SERVER)
	@valgrind ./$(BUILD)/$(TEST_SERVER)

stress: $(BUILD)/$(TEST_SERVER)
	@./$(BUILD)/$(TEST_SERVER) > $(BUILD)/output.log &
	@sleep 0.3
	tcpkali -c 200 -m "Some message" localhost:8000 --latency-connect --latency-first-byte -T 20
	@killall --signal SIGINT -w "$(TEST_SERVER)"
	@echo "----------- Server output -----------"
	@cat $(BUILD)/output.log

test: $(BUILD)/$(TEST_SERVER)
	@./$(BUILD)/$(TEST_SERVER) > $(BUILD)/output.log &
	@sleep 0.3
	@for TEST in $(TESTS); do python3 $$TEST; done
	@killall --signal SIGINT -w "$(TEST_SERVER)"
	@echo "----------- Server output -----------"
	@cat $(BUILD)/output.log

$(BUILD)/$(TEST_SERVER): $(TEST)/run.c $(BUILD)/libhh.a
	$(CC) $(TEST)/run.c -I $(CFLAGS) -o $@ -L$(BUILD) -l:libhh.a $(LDLIBS)

$(BUILD)/libhh.a: $(BUILD) $(OBJS)
	$(AR) -rcs $(BUILD)/libhh.a $(OBJS)

$(BUILD)/libhh.so: $(BUILD) $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(BUILD):
	mkdir $@

$(BUILD)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@
