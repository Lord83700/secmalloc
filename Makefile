# Variables
CC := gcc
CFLAGS := -Wall -Wextra -Werror -g3 -std=c99
CPPFLAGS := -I./include
LDFLAGS := 
LDLIBS := 

# Directories
SRC_DIR := src
INCLUDE_DIR := include
TEST_DIR := test
LIB_DIR := lib
OBJ_DIR := obj

# Source files
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Test files
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.c)
TEST_OBJECTS := $(TEST_SOURCES:$(TEST_DIR)/%.c=$(OBJ_DIR)/test_%.o)

# Libraries
STATIC_LIB := libmy_secmalloc.a
DYNAMIC_LIB := $(LIB_DIR)/libmy_secmalloc.so
TEST_EXEC := unit_tests

# Default target
.DEFAULT_GOAL := help

# Create directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

# Compile source objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -c $< -o $@

# Compile test objects
$(OBJ_DIR)/test_%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling test $<..."
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Static library for tests
$(STATIC_LIB): $(OBJECTS)
	@echo "Creating static library..."
	@ar rcs $@ $^
	@echo "Static library created: $@"

# Dynamic library for LD_PRELOAD
$(DYNAMIC_LIB): $(OBJECTS) | $(LIB_DIR)
	@echo "Creating dynamic library..."
	@$(CC) -shared -fPIC $^ -o $@
	@echo "Dynamic library created: $@"

# Test executable
$(TEST_EXEC): $(TEST_OBJECTS) $(STATIC_LIB)
	@echo "Linking tests..."
	@$(CC) $(CFLAGS) $(TEST_OBJECTS) -L. -lmy_secmalloc -lcriterion -o $@

# Targets
.PHONY: all clean static dynamic test tests_run help debug

help:
	@echo "Available targets:"
	@echo "  static      - Build static library"
	@echo "  dynamic     - Build dynamic library"
	@echo "  test        - Build and run all tests"
	@echo "  tests_run   - Same as test (Epitech convention)"
	@echo "  debug       - Build with debug info and run specific test"
	@echo "  clean       - Clean all generated files"
	@echo "  help        - Show this help"

static: clean $(STATIC_LIB)

dynamic: clean $(DYNAMIC_LIB)

test: $(TEST_EXEC)
	@echo "Running tests..."
	@./$(TEST_EXEC) --verbose

tests_run: test

# Debug target - run specific tests
debug: $(TEST_EXEC)
	@echo "Available test suites:"
	@./$(TEST_EXEC) --list
	@echo ""
	@echo "Run specific test with: ./$(TEST_EXEC) --filter=PATTERN"
	@echo "Example: ./$(TEST_EXEC) --filter=metapool"

# Progressive testing targets
test-mmap: $(TEST_EXEC)
	@echo "Testing mmap functionality..."
	@./$(TEST_EXEC) --filter='mmap*' --verbose

test-metapool: $(TEST_EXEC)
	@echo "Testing metapool initialization..."
	@./$(TEST_EXEC) --filter='metapool*' --verbose

test-datapool: $(TEST_EXEC)
	@echo "Testing datapool initialization..."
	@./$(TEST_EXEC) --filter='datapool*' --verbose

test-assign: $(TEST_EXEC)
	@echo "Testing metadata assignment..."
	@./$(TEST_EXEC) --filter='assign*' --verbose

test-add-block: $(TEST_EXEC)
	@echo "Testing add new metadata block..."
	@./$(TEST_EXEC) --filter='add_new_meta_block*' --verbose

test-check-free: $(TEST_EXEC)
	@echo "Testing check if block is free..."
	@./$(TEST_EXEC) --filter='check_if_metablock_is_free*' --verbose

test-check-size: $(TEST_EXEC)
	@echo "Testing get remaining size of pools..."
	@./$(TEST_EXEC) --filter='check_remain_size*' --verbose

test-malloc: $(TEST_EXEC)
	@echo "Testing malloc..."
	@./$(TEST_EXEC) --filter='check_malloc*' --verbose

test-realloc: $(TEST_EXEC)
	@echo "Testing realloc..."
	@./$(TEST_EXEC) --filter='check_realloc*' --verbose

test-canary: $(TEST_EXEC)
	@echo "Testing canary..."
	@./$(TEST_EXEC) --filter='check_canary*' --verbose

test-calloc: $(TEST_EXEC)
	@echo "Testing calloc..."
	@./$(TEST_EXEC) --filter='check_calloc*' --verbose




# Test with LD_PRELOAD
test-preload: $(DYNAMIC_LIB)
	@echo "Testing with LD_PRELOAD..."
	@echo "int main(){void*p=malloc(16);free(p);return 0;}" | gcc -x c - -o test_prog
	@LD_PRELOAD=./$(DYNAMIC_LIB) ./test_prog
	@rm -f test_prog

clean:
	@echo "Cleaning..."
	@rm -rf $(OBJ_DIR) $(STATIC_LIB) $(DYNAMIC_LIB) $(TEST_EXEC)
	@rm -f *.gcda *.gcno *.gcov
	@rm -f test_prog

# Dependencies
-include $(OBJECTS:.o=.d)
-include $(TEST_OBJECTS:.o=.d)
