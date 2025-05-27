#include <criterion/assert.h>
#include <criterion/internal/assert.h>
#include <criterion/logging.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <criterion/criterion.h>
#define _GNU_SOURCE
#include "../include/my_secmalloc.private.h"
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

Test(mmap, simple) {
  void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  cr_expect(ptr != NULL);
  int res = munmap(ptr, 4096);
  cr_expect(res == 0);
}

//Test(mmap, mremap) {
//  void *reserved = mmap(NULL,        // demande à mmap de choisir l'adresse
//                        (1UL << 30), // demande 1 Go d'espace d'adressage
//                        PROT_NONE,   // Protection = PROT_NONE car on réserve
//                        MAP_ANONYMOUS | MAP_PRIVATE |
//                            MAP_NORESERVE, // pas d'instanciation de la mémoire
//                        -1, 0              // Juste de la mémoire
//  );
//  cr_expect(reserved != MAP_FAILED);
//
//  size_t meta_size =
//      4096; // TODO: moyen plus joli pour avoir la taille d'une page
//
//  void *meta_pool = mremap(reserved, (1UL << 30), meta_size, 0);
//  cr_log_info("REGION MAPPÉ %p\n", meta_pool);
//  cr_expect(meta_pool != MAP_FAILED && meta_pool == reserved);
//
//  mprotect(meta_pool, meta_size, PROT_READ | PROT_WRITE);
//  memset(meta_pool, 'X', meta_size);
//
//  cr_assert(2600); // Assert TRUE style 2600$
//}

Test(metapool, test_init) {
  extern struct metadata_t *meta_pool;
  extern size_t meta_nb;

  init_metapool();

  cr_expect(meta_pool !=
            MAP_FAILED);   // Vérifie que la mémoire a bien été allouée
  cr_expect(meta_nb == 1); // On attend un seul bloc initialisé
  cr_expect(meta_pool[0].data == NULL);  // Aucun pointeur de données
  cr_expect(meta_pool[0].state == NONE); // Flag d’état à NONE (libre)

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
Test(assign_metapool_datapool, test_init) {
  extern struct metadata_t *meta_pool;
  extern void *data_pool;
  extern size_t data_size;

  init_metapool();
  init_datapool();
  assign_meta_block_to_data_as_free(&meta_pool[0], data_pool, data_size);
  cr_expect(meta_pool !=
            MAP_FAILED); // Vérifie que la mémoire a bien été allouée
  cr_expect(meta_pool[0].data == data_pool);     // Aucun pointeur de données
  cr_expect(meta_pool[0].state == FREE);         // Flag d’état à NONE (libre)
  cr_expect(meta_pool[0].datasize == data_size); // Taille initiale à zéro
  cr_expect(meta_pool[0].csize == 0);            // Taille initiale à zéro
  
  cr_log_info("[ASSIGN] Region Mappe %p\n", meta_pool);
  cr_log_info("[ASSIGN] Region Mappe %p\n", data_pool);

  cr_log_info("[ASSIGN] DataSize %ld\n", data_size);
  cr_log_info("[ASSIGN] Metadata data %p\n", meta_pool[0].data);
}

Test(add_new_meta_block, test_init) {
  extern struct metadata_t *meta_pool;
  extern size_t meta_nb;

  init_metapool();

  cr_expect(meta_pool !=
            MAP_FAILED);   // Vérifie que la mémoire a bien été allouée
  cr_expect(meta_nb == 1); // On attend un seul bloc initialisé
  cr_expect(meta_pool[0].data == NULL);  // Aucun pointeur de données
  cr_expect(meta_pool[0].state == NONE); // Flag d’état à NONE (libre)
  struct metadata_t *new_block = add_new_metadata_block();

  cr_expect(new_block != MAP_FAILED);
  cr_expect(meta_nb == 2);
  cr_expect(new_block->data == NULL);
  cr_expect(new_block->state == NONE);

  cr_expect(meta_pool[0].next == new_block);
  cr_expect(new_block->next == NULL);

  cr_log_info("[ADD-BLOCK] METADATA POOL MAPPE %p\n", meta_pool);
  cr_log_info("[ADD-BLOCK] METADATA MAPPE %p\n", &meta_pool[0]);
  cr_log_info("[ADD-BLOCK] METADATA NEXT %p\n", meta_pool[0].next);
  cr_log_info("[ADD-BLOCK] NEW BLOCK MAPPE %p\n", new_block);
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
  struct metadata_t *new_block = add_new_metadata_block();

  // Assigne le premier bloc comme FREE avec de la data
  assign_meta_block_to_data_as_free(&meta_pool[0], data_pool, 30);

  // Test : cherche un bloc libre de 16 octets
  size_t size_demanded = 16;
  struct metadata_t *found_block = check_if_a_metablock_is_free(size_demanded);

  cr_log_info("[ISFREE] DATA POOL %p\n", data_pool);
  cr_log_info("[ISFREE] FIRST BLOCK %p\n", &meta_pool[0]);
  cr_log_info("[ISFREE] SECOND BLOCK %p\n", &meta_pool[1]);
  cr_log_info("[ISFREE] NEW BLOCK %p\n", new_block);
  cr_log_info("[ISFREE] FOUND BLOCK %p\n", found_block);
  cr_log_info("[ISFREE] DATA SIZE %ld\n", data_size);

  cr_expect(found_block != NULL);                    // Un bloc a été trouvé
  cr_expect(found_block == &meta_pool[0]);           // C'est le premier bloc
  cr_expect(found_block->state == FREE);             // Il est libre
  cr_expect(found_block->datasize >= size_demanded); // Il est assez grand
}

Test(check_if_metablock_is_free, no_free_block) {
  extern struct metadata_t *meta_pool;

  init_metapool();
  // Ne pas assigner de data = reste NONE

  struct metadata_t *found_block = check_if_a_metablock_is_free(16);

  cr_expect(found_block == NULL); // Aucun bloc libre trouvé
}

Test(check_remain_size, test_init){
  extern struct metadata_t *meta_pool;
  extern void *data_pool;
  extern size_t data_size;
  extern size_t meta_nb;
  extern size_t meta_size;

  //Setup
  init_metapool();
  init_datapool();
  struct metadata_t *new_block = add_new_metadata_block();
  struct metadata_t *new_new_block = add_new_metadata_block();
  void *first_data_block = data_pool;
  void *second_data_block = first_data_block+40; //Pour tester je veux juste allouer 40
  void *third_data_block = second_data_block+40;

  cr_expect(new_block != NULL);
  cr_expect(new_new_block != NULL);
  cr_expect(first_data_block != NULL);
  cr_expect(second_data_block != NULL);
  cr_expect(third_data_block != NULL);

  //Assigne le premier bloc 
  assign_meta_block_to_data_as_free(&meta_pool[0], data_pool, 40);
  assign_meta_block_to_data_as_free(new_block, second_data_block, 40);
  assign_meta_block_to_data_as_free(new_new_block, third_data_block, 40);

  size_t remain_size_metapool = get_remain_size_of_metapool();
  size_t remain_size_datapool = get_remain_size_of_datapool();

  cr_log_info("[SIZE] REMAIN SIZE METAPOOL %ld\n", remain_size_metapool);
  cr_log_info("[SIZE] REMAIN SIZE DATAPOOL %ld\n", remain_size_datapool);
  cr_log_info("[SIZE] DATA POOL %p\n", data_pool);
  cr_log_info("[SIZE] FIRST BLOCK %p\n", &meta_pool[0]);
  cr_log_info("[SIZE] NEW BLOCK %p\n", new_block);
  cr_log_info("[SIZE] NEW NEW BLOCK %p\n", new_new_block);
  cr_log_info("[SIZE] SIZEOF FIRST BLOCK %ld\n", sizeof(meta_pool[0]));
  cr_log_info("[SIZE] SIZEOF STRUCT %ld\n", sizeof(struct metadata_t));

  cr_expect(remain_size_metapool == meta_size-216);
  cr_expect(remain_size_datapool == data_size-120);

}
