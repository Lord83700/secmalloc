#include <stdint.h>
#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_ALLOCS 1000
#define MAX_SIZE 4096

struct allocation {
  void *ptr;
  size_t size;
  int pattern;
};

void print(const char *msg) { write(1, msg, strlen(msg)); }
void print_ptr(void *ptr) {
  uintptr_t val = (uintptr_t)ptr;
  char buf[2 + sizeof(uintptr_t) * 2]; // "0x" + 2 caractères par byte
  buf[0] = '0';
  buf[1] = 'x';

  for (int i = sizeof(uintptr_t) * 2 - 1; i >= 0; i--) {
    int digit = val & 0xF;
    buf[2 + i] = digit < 10 ? ('0' + digit) : ('a' + digit - 10);
    val >>= 4;
  }

  write(1, buf, sizeof(buf));
}
void print_int(int val) {
  char buf[32];
  int len = 0;

  // Conversion manuelle (itoa simplifiée, sans gestion négatifs ici)
  if (val == 0) {
    buf[len++] = '0';
  } else {
    int tmp = val;
    char rev[32];
    int i = 0;
    while (tmp > 0) {
      rev[i++] = '0' + (tmp % 10);
      tmp /= 10;
    }
    // Reverse le résultat
    while (i > 0) {
      buf[len++] = rev[--i];
    }
  }

  write(1, buf, len);
}

void print_size_t(size_t n) {
  char buf[32]; // Assez grand pour 64 bits
  int i = 31;
  buf[i--] = '\0';

  if (n == 0) {
    buf[i] = '0';
    write(1, &buf[i], 1);
    return;
  }

  while (n > 0 && i >= 0) {
    buf[i--] = '0' + (n % 10);
    n /= 10;
  }

  write(1, &buf[i + 1], 31 - i);
}

void test_basic_alloc_free() {
  print("=== Test 1: Basic allocation/free ===\n");

  void *ptrs[100];

  for (int i = 0; i < 100; i++) {
    size_t size = (i + 1) * 16;
    ptrs[i] = malloc(size);
    print("MALLOC PASSE ");
    print_int(i);
    print(" fois");
    print(" pour ");
    print_size_t(size);
    print(" taille \n");
    if (!ptrs[i]) {
      print("FAIL: malloc returned NULL\n");
      return;
    }
    memset(ptrs[i], i % 256, size);
  }

  for (int i = 0; i < 100; i++) {
    size_t size = (i + 1) * 16;
    unsigned char *data = (unsigned char *)ptrs[i];
    for (size_t j = 0; j < size; j++) {
      if (data[j] != (i % 256)) {
        print("FAIL: Data corruption\n");
        return;
      }
    }
  }

  for (int i = 99; i >= 0; i--) {
    print("PTR BEFORE FREE ");
    print_ptr(ptrs[i]);
    print("\n");
    free(ptrs[i]);
  }

  print("PASS: Basic allocation/free\n");
}

void test_fragmentation() {
  print("=== Test 2: Fragmentation and reuse ===\n");

  void *ptrs[50];

  for (int i = 0; i < 50; i++) {
    ptrs[i] = malloc(100);
    if (!ptrs[i]) {
      print("FAIL: malloc(100) returned NULL\n");
      return;
    }
    print("PTR CREATED ");
    print_ptr(ptrs[i]);
    print("\n");
    memset(ptrs[i], i, 100);
  }

  for (int i = 0; i < 50; i += 2) {
    print("PTR BEFORE FREE ");
    print_ptr(ptrs[i]);
    print("\n");
    free(ptrs[i]);
    ptrs[i] = NULL;
  }

  for (int i = 0; i < 50; i += 2) {
    ptrs[i] = malloc(100);
    if (!ptrs[i]) {
      print("FAIL: Reallocation failed\n");
      return;
    }
    print("PTR AFTER FREE ");
    print_ptr(ptrs[i]);
    print("\n");
    memset(ptrs[i], i, 100);
  }

  for (int i = 1; i < 50; i += 2) {
    unsigned char *data = (unsigned char *)ptrs[i];
    for (int j = 0; j < 100; j++) {
      if (data[j] != (unsigned char)i) {
        print("FAIL: Data corruption in odd block ");
        print("at block i=");
        print_int(i);
        print(", index j=");
        print_int(j);
        print(", got=");
        print_int(data[j]);
        print(", expected=");
        print_int(i);
        print("\n");
        return;
      }
    }
  }

  for (int i = 0; i < 50; i++) {
    if (ptrs[i])
      free(ptrs[i]);
  }

  print("PASS: Fragmentation and reuse\n");
}

void test_random_stress() {
  print("=== Test 3: Random stress test ===\n");

  struct allocation allocs[MAX_ALLOCS];
  int active_allocs = 0;
  srand(time(NULL));

  for (int iteration = 0; iteration < 5000; iteration++) {
    if (active_allocs == 0 || (active_allocs < MAX_ALLOCS && rand() % 2)) {
      size_t size = 1 + (rand() % MAX_SIZE);
      void *ptr = malloc(size);
      if (ptr) {
        allocs[active_allocs].ptr = ptr;
        allocs[active_allocs].size = size;
        allocs[active_allocs].pattern = rand() % 256;
        memset(ptr, allocs[active_allocs].pattern, size);
        active_allocs++;
      }
    } else {
      print("Active alloc ");
      print_int(active_allocs);
      print("\n");
      int idx = rand() % active_allocs;
      unsigned char *data = (unsigned char *)allocs[idx].ptr;
      for (size_t i = 0; i < allocs[idx].size; i++) {
        if (data[i] != allocs[idx].pattern) {
          print_int(data[i]);
          print("\n");
          print_int(allocs[idx].pattern);
          print("\n");
          print("FAIL: Data corruption before free\n");
          return;
        }
      }
      print("Freeing block of size ");
      print_int(allocs[idx].size);
      print(" at index ");
      print_int(idx);
      print("\n");
      free(allocs[idx].ptr);
      allocs[idx] = allocs[active_allocs - 1];
      active_allocs--;
    }

    if (iteration % 500 == 0) {
      for (int i = 0; i < active_allocs; i++) {
        unsigned char *data = (unsigned char *)allocs[i].ptr;
        for (size_t j = 0; j < allocs[i].size; j++) {
          if (data[j] != allocs[i].pattern) {
            print("FAIL: Data corruption during stress\n");
            return;
          }
        }
      }
    }
  }

  for (int i = 0; i < active_allocs; i++) {
    free(allocs[i].ptr);
  }

  print("PASS: Random stress test\n");
}

void test_calloc() {
  print("=== Test 4: Calloc test ===\n");

  for (int i = 1; i <= 100; i++) {
    void *ptr = calloc(i, sizeof(int));
    if (!ptr) {
      print("FAIL: calloc returned NULL\n");
      return;
    }
    int *data = (int *)ptr;
    for (int j = 0; j < i; j++) {
      if (data[j] != 0) {
        print("FAIL: calloc not zeroed\n");
        free(ptr);
        return;
      }
    }
    free(ptr);
  }

  print("PASS: Calloc test\n");
}

void test_realloc() {
  print("=== Test 5: Realloc test ===\n");

  char *ptr = malloc(100);
  if (!ptr) {
    print("FAIL: Initial malloc failed\n");
    return;
  }

  strcpy(ptr, "Hello, World!");

  ptr = realloc(ptr, 200);
  if (!ptr) {
    print("FAIL: realloc expansion failed\n");
    return;
  }

  if (strcmp(ptr, "Hello, World!") != 0) {
    print("FAIL: Data lost during realloc\n");
    free(ptr);
    return;
  }

  ptr = realloc(ptr, 50);
  if (!ptr) {
    print("FAIL: realloc shrinking failed\n");
    return;
  }

  if (strncmp(ptr, "Hello, World!", 13) != 0) {
    print("FAIL: Data corrupted during shrinking\n");
    free(ptr);
    return;
  }

  free(ptr);
  print("PASS: Realloc test\n");
}

void test_edge_cases() {
  print("=== Test 6: Edge cases ===\n");

  void *ptr = malloc(0);
  if (ptr != NULL)
    free(ptr);

  free(NULL);

  ptr = realloc(NULL, 100);
  if (!ptr) {
    print("FAIL: realloc(NULL, 100) failed\n");
    return;
  }
  free(ptr);

  ptr = malloc(100);
  if (!ptr) {
    print("FAIL: malloc for realloc test failed\n");
    return;
  }
  ptr = realloc(ptr, 0);

  ptr = calloc(SIZE_MAX, 2);
  if (ptr != NULL) {
    print("FAIL: calloc overflow should have failed\n");
    free(ptr);
    return;
  }

  print("PASS: Edge cases\n");
}

int main() {
  print("Starting comprehensive malloc stress tests...\n\n");

  test_basic_alloc_free();
  test_fragmentation();
  test_random_stress();
  test_calloc();
  test_realloc();
  test_edge_cases();

  print("\n=== All tests completed ===\n");
  print("If you see this message, your malloc implementation is robust.\n");

  return 0;
}
