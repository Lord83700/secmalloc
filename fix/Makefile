CC = gcc
CFLAGS = -Wall -Wextra -g -fPIC
LDFLAGS = -shared

# Fichiers sources
SOURCES = my_secmalloc.c
HEADERS = include/my_secmalloc.h include/my_secmalloc.private.h
OBJECTS = $(SOURCES:.c=.o)

# Fichiers de test
TEST_SOURCES = test.c stress_test.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)

# Cibles
LIBRARY = libmy_secmalloc.so
TEST_STATIC = test_static
TEST_PRELOAD = stress_test
CRITERION_TEST = test_criterion

.PHONY: all clean test test-static test-preload test-ls help

all: $(LIBRARY) $(TEST_STATIC) $(TEST_PRELOAD)

# Compilation de la bibliothèque partagée
$(LIBRARY): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

# Compilation des objets
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test statique (lié directement)
$(TEST_STATIC): stress_test.c $(OBJECTS)
	$(CC) $(CFLAGS) -DUSE_MY_MALLOC -o $@ $^

# Test avec LD_PRELOAD
$(TEST_PRELOAD): stress_test.c
	$(CC) $(CFLAGS) -DUSE_SYSTEM_MALLOC -o $@ $<

# Test avec Criterion (vos tests existants)
$(CRITERION_TEST): test.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ -lcriterion

# Tests
test: test-static test-preload test-criterion

test-static: $(TEST_STATIC)
	@echo "=== Running static tests ==="
	./$(TEST_STATIC)

test-preload: $(LIBRARY) $(TEST_PRELOAD)
	@echo "=== Running LD_PRELOAD tests ==="
	LD_PRELOAD=./$(LIBRARY) ./$(TEST_PRELOAD)

test-criterion: $(CRITERION_TEST)
	@echo "=== Running Criterion tests ==="
	./$(CRITERION_TEST)

# Test avec de vrais programmes
test-ls: $(LIBRARY)
	@echo "=== Testing with ls command ==="
	LD_PRELOAD=./$(LIBRARY) ls -la /tmp

test-real-programs: $(LIBRARY)
	@echo "=== Testing with various real programs ==="
	@echo "Testing ls..."
	LD_PRELOAD=./$(LIBRARY) ls -la > /dev/null && echo "ls: OK" || echo "ls: FAILED"
	@echo "Testing find..."
	LD_PRELOAD=./$(LIBRARY) find /tmp -name "*.tmp" > /dev/null 2>&1 && echo "find: OK" || echo "find: FAILED"
	@echo "Testing grep..."
	LD_PRELOAD=./$(LIBRARY) grep -r "test" /dev/null 2>&1 && echo "grep: OK" || echo "grep: FAILED"
	@echo "Testing cat..."
	LD_PRELOAD=./$(LIBRARY) cat /etc/hostname > /dev/null && echo "cat: OK" || echo "cat: FAILED"

# Test de performance
benchmark: $(LIBRARY) $(TEST_PRELOAD)
	@echo "=== Performance comparison ==="
	@echo "System malloc:"
	time ./$(TEST_PRELOAD)
	@echo "Your malloc:"
	time LD_PRELOAD=./$(LIBRARY) ./$(TEST_PRELOAD)

# Debugging avec gdb
debug-static: $(TEST_STATIC)
	gdb ./$(TEST_STATIC)

debug-preload: $(LIBRARY) $(TEST_PRELOAD)
	LD_PRELOAD=./$(LIBRARY) gdb ./$(TEST_PRELOAD)

# Analyse mémoire avec valgrind
valgrind-static: $(TEST_STATIC)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_STATIC)

# Vérification avec strace
strace-ls: $(LIBRARY)
	LD_PRELOAD=./$(LIBRARY) strace -e trace=mmap,munmap,mremap,mprotect ls /tmp

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS)
	rm -f $(LIBRARY) $(TEST_STATIC) $(TEST_PRELOAD) $(CRITERION_TEST)

help:
	@echo "Available targets:"
	@echo "  all                 - Build everything"
	@echo "  $(LIBRARY)          - Build shared library"
	@echo "  test                -