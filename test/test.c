#define _GNU_SOURCE
#include "../include/my_secmalloc.private.h"
#include <criterion/assert.h>
#include <criterion/criterion.h>
#include <criterion/internal/assert.h>
#include <criterion/internal/test.h>
#include <criterion/logging.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#
Test(mmap, simple) {
  void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  cr_expect(ptr != NULL);
  int res = munmap(ptr, 4096);
  cr_expect(res == 0);
}

// Test(mmap, mremap) {
//   void *reserved = mmap(NULL,        // demande à mmap de choisir l'adresse
//                         (1UL << 30), // demande 1 Go d'espace d'adressage
//                         PROT_NONE,   // Protection = PROT_NONE car on réserve
//                         MAP_ANONYMOUS | MAP_PRIVATE |
//                             MAP_NORESERVE, // pas d'instanciation de la
//                             mémoire
//                         -1, 0              // Juste de la mémoire
//   );
//   cr_expect(reserved != MAP_FAILED);
//
//   size_t meta_size =
//       4096; // TODO: moyen plus joli pour avoir la taille d'une page
//
//   void *meta_pool = mremap(reserved, (1UL << 30), meta_size, 0);
//   cr_log_info("REGION MAPPÉ %p\n", meta_pool);
//   cr_expect(meta_pool != MAP_FAILED && meta_pool == reserved);
//
//   mprotect(meta_pool, meta_size, PROT_READ | PROT_WRITE);
//   memset(meta_pool, 'X', meta_size);
//
//   cr_assert(2600); // Assert TRUE style 2600$
// }

Test(metapool, test_init) {
  extern struct metadata_t *meta_pool;
  extern size_t meta_nb;

  init_metapool();

  cr_expect(meta_pool !=
            MAP_FAILED);   // Vérifie que la mémoire a bien été allouée
  cr_expect(meta_nb == 1); // On attend un seul bloc initialisé
  cr_expect(meta_pool->data == NULL);  // Aucun pointeur de données
  cr_expect(meta_pool->state == NONE); // Flag d’état à NONE (libre)

  cr_log_info("[METAPOOL] Region Mappe %p\n", meta_pool);
}
Test(datapool, test_init) {
  extern void *data_pool;
  extern size_t data_size;

  init_datapool();

  cr_expect(data_pool !=
            MAP_FAILED);        // Vérifie que la mémoire a bien été allouée
  cr_expect(data_size == 4096); // Aucun pointeur de données
  cr_log_info("[DATAPOOL] Region Mappe %p\n", data_pool);
}

Test(add_new_meta_block, test_init) {
  extern struct metadata_t *meta_pool;
  extern size_t meta_nb;

  init_metapool();

  cr_expect(meta_pool !=
            MAP_FAILED);   // Vérifie que la mémoire a bien été allouée
  cr_expect(meta_nb == 1); // On attend un seul bloc initialisé
  cr_expect(meta_pool->data == NULL);  // Aucun pointeur de données
  cr_expect(meta_pool->state == NONE); // Flag d’état à NONE (libre)
  struct metadata_t *new_block = add_new_metadata_block();

  cr_expect(new_block != MAP_FAILED);
  cr_expect(meta_nb == 2);
  cr_expect(new_block->data == NULL);
  cr_expect(new_block->state == NONE);

  cr_expect(meta_pool->next == new_block);

  struct metadata_t *second_block = add_new_metadata_block();
  cr_expect(second_block != MAP_FAILED);
  cr_expect(meta_nb == 3);
  cr_expect(second_block->state == NONE);

  cr_expect(new_block->next == second_block);

  cr_log_info("[ADD-BLOCK] METADATA POOL MAPPE %p\n", meta_pool);
  cr_log_info("[ADD-BLOCK] METADATA MAPPE %p\n", meta_pool);
  cr_log_info("[ADD-BLOCK] METADATA NEXT %p\n", meta_pool->next);
  cr_log_info("[ADD-BLOCK] NEW BLOCK MAPPE %p\n", new_block);
  cr_log_info("[ADD-BLOCK] NEW NEXT BLOCK MAPPE %p\n", new_block->next);
  cr_log_info("[ADD-BLOCK] NEW PREV BLOCK MAPPE %p\n", new_block->prev);
  cr_log_info("[ADD-BLOCK] SECOND NEW BLOCK MAPPE %p\n", second_block);
  cr_log_info("[ADD-BLOCK] SECOND NEW PREV BLOCK MAPPE %p\n",
              second_block->prev);
  cr_log_info("[ADD-BLOCK] SIZEOF BLOCK %ld\n", sizeof(meta_pool[0]));
}

Test(check_if_metablock_is_free, test_init) {
  extern struct metadata_t *meta_pool;
  extern size_t meta_nb;
  extern void *data_pool;
  extern size_t data_size;

  // Setup : crée metapool + datapool
  init_metapool();
  init_datapool();
  cr_log_info("[ISFREE] DATA POOL %p\n", data_pool);
  meta_pool->data = data_pool;
  meta_pool->datasize = 32;
  struct metadata_t *new_block = add_new_metadata_block();
  cr_log_info("[ISFREE] Pool init and new block added");
  cr_log_info("[ISFREE] NEW BLOCK %p\n", new_block);
  cr_log_info("[ISFREE] FIRST BLOCK %p\n", meta_pool);
  cr_log_info("[ISFREE] SECOND BLOCK %p\n", meta_pool->next);
  new_block->data = meta_pool->data + meta_pool->datasize + meta_pool->csize;
  cr_log_info("[ISFREE] SIZEOF %ld", sizeof(struct metadata_t));

  // Assigne le premier bloc comme FREE avec de la data
  // assign_meta_block_to_data_as_free(&meta_pool[0], data_pool, 30);

  my_free(meta_pool->data);

  // Test : cherche un bloc libre de 16 octets
  size_t size_demanded = 16;
  struct metadata_t *found_block = check_if_a_metablock_is_free(size_demanded);

  cr_log_info("[ISFREE] FOUND BLOCK %p\n", found_block);
  cr_log_info("[ISFREE] DATA SIZE %ld\n", data_size);

  cr_expect(found_block != NULL);                    // Un bloc a été trouvé
  cr_expect(found_block == &meta_pool[0]);           // C'est le premier bloc
  cr_expect(found_block->datasize >= size_demanded); // Il est assez grand
}

Test(check_if_metablock_is_free, no_free_block) {
  extern struct metadata_t *meta_pool;

  init_metapool();
  // Ne pas assigner de data = reste NONE

  struct metadata_t *found_block = check_if_a_metablock_is_free(16);

  cr_expect(found_block == NULL); // Aucun bloc libre trouvé
}

Test(check_remain_size, test_init) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;
  extern size_t data_size;
  extern size_t meta_nb;
  extern size_t meta_size;

  // Setup
  init_metapool();
  init_datapool();
  struct metadata_t *new_block = add_new_metadata_block();
  struct metadata_t *new_new_block = add_new_metadata_block();
  void *first_data_block = data_pool;
  void *second_data_block =
      first_data_block + 40; // Pour tester je veux juste allouer 40
  void *third_data_block = second_data_block + 40;

  meta_pool->data = first_data_block;
  new_block->data = second_data_block;
  new_new_block->data = third_data_block;

  meta_pool->datasize = 8;
  new_block->datasize = 8;
  new_new_block->datasize = 8;

  cr_expect(new_block != NULL);
  cr_expect(new_new_block != NULL);
  cr_expect(first_data_block != NULL);
  cr_expect(second_data_block != NULL);
  cr_expect(third_data_block != NULL);

  // Assigne le premier bloc
  // assign_meta_block_to_data_as_free(&meta_pool[0], data_pool, 40);
  // assign_meta_block_to_data_as_free(new_block, second_data_block, 40);
  // assign_meta_block_to_data_as_free(new_new_block, third_data_block, 40);

  size_t remain_size_metapool = get_remain_size_of_metapool();
  size_t remain_size_datapool = get_remain_size_of_datapool();

  cr_log_info("[SIZE] REMAIN SIZE METAPOOL %ld\n", remain_size_metapool);
  cr_log_info("[SIZE] REMAIN SIZE DATAPOOL %ld\n", remain_size_datapool);
  cr_log_info("[SIZE] DATA POOL %p\n", data_pool);
  cr_log_info("[SIZE] FIRST BLOCK %p\n", meta_pool);
  cr_log_info("[SIZE] NEW BLOCK %p\n", new_block);
  cr_log_info("[SIZE] NEW NEW BLOCK %p\n", new_new_block);
  cr_log_info("[SIZE] SIZEOF STRUCT %ld\n", sizeof(struct metadata_t));

  cr_expect(remain_size_metapool == meta_size - 240);
  cr_expect(remain_size_datapool == data_size - 120);
}
Test(check_malloc, test_init) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;

  char *my_data_block = my_malloc(42);

  cr_log_info("[MALLOC] Meta pool %p\n", meta_pool);
  cr_log_info("[MALLOC] Data pool %p\n", data_pool);
  cr_log_info("[MALLOC] DATA BLOCK %p\n", my_data_block);
  cr_expect(my_data_block != NULL);
  my_data_block = strcpy(my_data_block, "Test1212");
  cr_expect(strcmp(my_data_block, "Test1212") == 0);
  cr_log_info("[MALLOC] CHAR %s\n", my_data_block);

  char *my_second_data_block = my_malloc(42);

  cr_log_info("[MALLOC] SECOND DATA BLOCK %p\n", my_second_data_block);
  cr_expect(my_second_data_block != NULL);
  cr_expect(my_second_data_block == (my_data_block + 80));

  my_second_data_block = "Test1313";
  cr_expect(strcmp(my_second_data_block, "Test1313") == 0);
  cr_log_info("[MALLOC] SECOND CHAR %s\n", my_second_data_block);

  my_free(my_data_block);
  cr_log_info("[MALLOC] DATA FREED\n");
  cr_log_info("[MALLOC] CHAR FREE %s\n", my_data_block);

  my_data_block = my_malloc(42);
  cr_log_info("[MALLOC] DATA BLOCK %p\n", my_data_block);
  cr_expect(my_data_block != NULL);
  my_data_block = strcpy(my_data_block, "AFTER FREE");
  cr_expect(strcmp(my_data_block, "AFTER FREE") == 0);
  cr_log_info("[MALLOC] CHAR %s\n", my_data_block);
}
Test(check_malloc, with_three_block_and_free_second) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;

  // Init un block
  char *my_data_block = my_malloc(42);

  cr_log_info("[MALLOC] Meta pool %p\n", meta_pool);
  cr_log_info("[MALLOC] Data pool %p\n", data_pool);
  cr_log_info("[MALLOC] DATA BLOCK %p\n", my_data_block);
  cr_expect(my_data_block != NULL);
  my_data_block = strcpy(my_data_block, "Test1212");
  cr_expect(strcmp(my_data_block, "Test1212") == 0);
  cr_log_info("[MALLOC] CHAR %s\n", my_data_block);

  // J'ajoute un block
  char *my_second_data_block = my_malloc(42);

  cr_log_info("[MALLOC] SECOND METADATA %p\n", meta_pool->next);
  cr_log_info("[MALLOC] SECOND DATA BLOCK %p\n", my_second_data_block);
  cr_expect(my_second_data_block != NULL);
  cr_expect(my_second_data_block == (my_data_block + 80));

  my_second_data_block = strcpy(my_second_data_block, "Test1313");
  cr_expect(strcmp(my_second_data_block, "Test1313") == 0);
  cr_log_info("[MALLOC] SECOND CHAR %s\n", my_second_data_block);

  char *my_third_data_block = my_malloc(42);
  cr_log_info("[MALLOC] THIRD METADATA %p\n", meta_pool->next->next);
  cr_log_info("[MALLOC] THIRD DATA BLOCK %p\n", my_third_data_block);
  cr_expect(my_third_data_block != NULL);
  my_third_data_block = strcpy(my_third_data_block, "Test1414");
  cr_expect(strcmp(my_third_data_block, "Test1414") == 0);
  cr_log_info("[MALLOC] THIRD CHAR %s\n", my_third_data_block);

  my_free(my_second_data_block);
  cr_log_info("[MALLOC] DATA FREED\n");
  cr_log_info("[MALLOC] SECOND CHAR FREE %s\n", my_second_data_block);
  cr_expect(strcmp(my_second_data_block, "") == 0);

  char *new_block = my_malloc(42);
  cr_expect(new_block != NULL);
  cr_log_info("[MALLOC] NEW DATA BLOCK %p\n", new_block);
  new_block = strcpy(new_block, "AFTER FREE");
  cr_expect(strcmp(new_block, "AFTER FREE") == 0);
  cr_log_info("[MALLOC] CHAR %s\n", new_block);
}
Test(check_malloc, with_three_block_and_free_last) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;

  // Init un block
  char *my_data_block = my_malloc(42);

  cr_log_info("[MALLOC] Meta pool %p\n", meta_pool);
  cr_log_info("[MALLOC] Data pool %p\n", data_pool);
  cr_log_info("[MALLOC] DATA BLOCK %p\n", my_data_block);
  cr_expect(my_data_block != NULL);
  my_data_block = strcpy(my_data_block, "Test1212");
  cr_expect(strcmp(my_data_block, "Test1212") == 0);
  cr_log_info("[MALLOC] CHAR %s\n", my_data_block);

  // J'ajoute un block
  char *my_second_data_block = my_malloc(42);

  cr_log_info("[MALLOC] SECOND METADATA %p\n", meta_pool->next);
  cr_log_info("[MALLOC] SECOND DATA BLOCK %p\n", my_second_data_block);
  cr_expect(my_second_data_block != NULL);
  cr_expect(my_second_data_block == (my_data_block + 80));

  my_second_data_block = strcpy(my_second_data_block, "Test1313");
  cr_expect(strcmp(my_second_data_block, "Test1313") == 0);
  cr_log_info("[MALLOC] SECOND CHAR %s\n", my_second_data_block);

  char *my_third_data_block = my_malloc(42);
  cr_log_info("[MALLOC] THIRD METADATA %p\n", meta_pool->next->next);
  cr_log_info("[MALLOC] THIRD DATA BLOCK %p\n", my_third_data_block);
  cr_expect(my_third_data_block != NULL);
  my_third_data_block = strcpy(my_third_data_block, "Test1414");
  cr_expect(strcmp(my_third_data_block, "Test1414") == 0);
  cr_log_info("[MALLOC] THIRD CHAR %s\n", my_third_data_block);

  my_free(my_third_data_block);
  cr_log_info("[MALLOC] DATA FREED\n");
  cr_log_info("[MALLOC] THIRD CHAR FREE %s\n", my_third_data_block);
  cr_expect(strcmp(my_third_data_block, "") == 0);

  char *new_block = my_malloc(42);
  cr_expect(new_block != NULL);
  cr_log_info("[MALLOC] NEW DATA BLOCK %p\n", new_block);
  new_block = strcpy(new_block, "AFTER FREE");
  cr_expect(strcmp(new_block, "AFTER FREE") == 0);
  cr_log_info("[MALLOC] CHAR %s\n", new_block);
}
Test(check_realloc, test_init) {
  extern struct metadata_t *meta_pool;
  char *first_block = my_malloc(42);
  cr_expect(first_block != NULL);
  char *second_block = my_malloc(42);
  cr_expect(second_block != NULL);
  cr_log_info("[REALLOC] SECOND BLOCK %p\n", second_block);
  char *third_block = my_malloc(42);
  cr_expect(third_block != NULL);

  char *realloc_block = my_realloc(second_block, 32);
  cr_log_info("[REALLOC] REALLOC BLOCK %p\n", realloc_block);
  cr_expect(realloc_block == second_block);
  cr_log_info("[REALLOC] DATASIZE %ld\n", meta_pool->next->datasize);
  cr_expect(meta_pool->next->datasize == 32);
}
Test(check_realloc, add_with_the_block_at_the_end) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;
  // Add no space left
  char *first_block = my_malloc(42);
  cr_expect(first_block != NULL);
  char *second_block = my_malloc(42);
  cr_expect(second_block != NULL);
  char *third_block = my_malloc(42);
  cr_expect(third_block != NULL);
  cr_log_info("[REALLOC] THIRD DATA BLOCK %p\n", third_block);

  // Add if the block is at the end
  char *second_realloc_block = my_realloc(third_block, 53);
  cr_log_info("[REALLOC] THIRD REALLOC DATA BLOCK %p\n", second_realloc_block);
  cr_expect(second_realloc_block == third_block);
  cr_log_info("[REALLOC] DATASIZE THIRD BLOCK %ld\n",
              meta_pool->next->next->datasize);
  cr_expect(meta_pool->next->next->datasize == 56);

  // Ca pete ici
  cr_log_info(
      "THIRD METADATA BECOME THE SECOND BECAUSE THE SECOND WILL BE FREED");
  char *realloc_block = my_realloc(second_block, 68);
  cr_log_info("[REALLOC] REALLOC BLOCK %p\n", realloc_block);
  cr_log_info("[REALLOC] FIRST METAPOOL %p\n", meta_pool);
  cr_log_info(
      "[REALLOC] SECOND METAPOOL THAT POINT TO THE THIRD DATA BLOCK %p\n",
      meta_pool->next);
  cr_log_info("[REALLOC] THIRD METAPOOL %p\n", meta_pool->next->next);
  cr_expect(realloc_block == meta_pool->next->next->data);
  cr_log_info("[REALLOC] DATASIZE %ld\n", meta_pool->next->next->datasize);
  cr_expect(meta_pool->next->next->datasize == 72);
}
Test(check_realloc, reduce_and_add) {
  // Reduit et ensuite on ajoute
  extern struct metadata_t *meta_pool;
  extern void *data_pool;

  // Add no space left
  char *first_block = my_malloc(42);
  cr_expect(first_block != NULL);
  char *second_block = my_malloc(42);
  cr_expect(second_block != NULL);
  char *third_block = my_malloc(42);
  cr_expect(third_block != NULL);

  // Reduit de 10
  char *realloc_block = my_realloc(second_block, 32);
  cr_expect(realloc_block == second_block);
  cr_log_info("[REALLOC] DATASIZE %ld\n", meta_pool->next->datasize);
  cr_expect(meta_pool->next->datasize == 32);

  // Augmente de 10
  char *second_realloc_block = my_realloc(realloc_block, 42);
  cr_expect(second_realloc_block == second_block);
  cr_log_info("[REALLOC] DATASIZE %ld\n", meta_pool->next->datasize);
  cr_expect(meta_pool->next->datasize == 48);
}
Test(check_canary, test_init) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;

  char *first_block = my_malloc(42);
  cr_expect(first_block != NULL);
  char *second_block = my_malloc(60);
  cr_expect(second_block != NULL);
  char *third_block = my_malloc(42);
  cr_expect(third_block != NULL);

  second_block =
      strcpy(second_block, "DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF");

  // cr_log_info("[CANARY] CHAR %s\n", second_block);

  // for (size_t i =0; i<32; i++){
  //   cr_log_info("[CANARY] SECOND CANARY %02x\n", meta_pool[1].canary[i]);
  // }
  unsigned char buffer[92];

  // memcpy(buffer, second_block+60, 32);

  // for (size_t i =0; i<32; i++){
  //   cr_log_info("[CANARY] CANARY COPIED %02x\n", buffer[i]);
  // }
  memset(second_block, 'A', 62);

  memcpy(buffer, second_block + 60, 32);

  // for (size_t i =0; i<32; i++){
  //   cr_log_info("[CANARY] CANARY MODIFIED %02x\n", buffer[i]);
  // }
  cr_expect(buffer != meta_pool->next->canary);
}

Test(check_calloc, test_init) {
  char *first_block = my_calloc(5, 10);
  cr_expect(first_block != NULL);

  first_block = strcpy(first_block, "Test1212");
  cr_expect(!(strcmp(first_block, "Test1212")));
}

Test(check_free, test_init) {
  extern struct metadata_t *meta_pool;

  char *ptrs[15];

  for (int i = 0; i < 15; i++) {
    ptrs[i] = my_malloc(100);
    cr_log_info("PTR %p\n", ptrs[i]);
    strcpy(ptrs[i], "AAAAAAAAAAAAAAA");
    cr_expect(strcmp(ptrs[i], "AAAAAAAAAAAAAAA") == 0);
  }
  cr_log_info("-------------------------");

  for (int i = 0; i < 15; i++) {
    cr_log_info("PTR %p\n", ptrs[i]);
    my_free(ptrs[i]);
    cr_log_info("CHAR %s\n", (char *)ptrs[i]);
    cr_expect(strcmp(ptrs[i], "") == 0);
    ptrs[i] = NULL;
  }
  cr_log_info("-------------------------");

  for (int i = 0; i < 15; i++) {
    ptrs[i] = my_malloc(100);
    strcpy(ptrs[i], "AAAAAAAAAAAAAAA");
    cr_expect(strcmp(ptrs[i], "AAAAAAAAAAAAAAA") == 0);
    cr_log_info("PTR %p\n", ptrs[i]);
  }
}
Test(check_free, one_of_two_block) {
  extern struct metadata_t *meta_pool;

  char *ptrs[15];
  char *other[20];
  int i = 0;

  for (int i = 0; i < 15; i++) {
    ptrs[i] = my_malloc(100);
    cr_log_info("PTR %p\n", ptrs[i]);
    strcpy(ptrs[i], "AAAAAAAAAAAAAAA");
    cr_expect(strcmp(ptrs[i], "AAAAAAAAAAAAAAA") == 0);
  }
  cr_log_info("-------------------------");

  int count = 0;

  for (int i = 0; i < 15; i += 2) {
    cr_log_info("PTR %p\n", ptrs[i]);
    my_free(ptrs[i]);
    cr_log_info("CHAR %s\n", (char *)ptrs[i]);
    cr_expect(strcmp(ptrs[i], "") == 0);
    ptrs[i] = NULL;
    count++;
  }
  cr_log_info("-------------------------");

  for (; count > 0; count--){
    other[i] = my_malloc(100);
    cr_log_info("PTR %p\n", other[i]);
    i++;
  }
}
