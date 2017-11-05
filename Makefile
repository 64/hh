BUILD := build
INCLUDE := include
SRC := src
TEST := test

CFLAGS += -Wall -Wextra -Wpedantic -Iinclude -g
LDLIBS += -ls2n -lcrypto -pthread

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

test: $(BUILD)/run
	@./$(BUILD)/run &
	@sleep 0.2
	@for TEST in $(TESTS); do python3 $$TEST; done
	@pkill --signal SIGINT -f "./$(BUILD)/run"
	@sleep 0.3

$(BUILD)/run: $(TEST)/run.c $(BUILD)/libhh.a
	$(CC) $(TEST)/run.c -I $(CFLAGS) -o $@ -L$(BUILD) -l:libhh.a $(LDLIBS)

$(BUILD)/libhh.a: $(BUILD) $(OBJS)
	$(AR) -rcs $(BUILD)/libhh.a $(OBJS)

$(BUILD)/libhh.so: $(BUILD) $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(BUILD):
	mkdir $@

$(BUILD)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@
