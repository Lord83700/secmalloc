#include <stddef.h>
#define _GNU_SOURCE
#include "../include/my_secmalloc.private.h"
#include <alloca.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define MAX_META_POOL_SIZE (1 << 30)
#define MAX_DATA_POOL_SIZE (64l << 30)

size_t struct_size = sizeof(struct metadata_t);
void *data_pool = NULL;
size_t meta_size = 0;
size_t data_size = 0;
struct metadata_t *meta_pool = NULL;
size_t meta_nb = 0;

unsigned char *gen_canary(unsigned char *buffer, size_t size) {
  for (size_t i = 0; i < size; i++) {
    buffer[i] = 0xDE; // ou pattern de ton choix
  }

  return buffer;
}

void init_metapool(void) {
  void *reserved = mmap(NULL, (1 << 30), PROT_NONE,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1,
                        0); // A changer la prot

  meta_size = 4096;

  meta_pool = (struct metadata_t *)mremap(reserved, (1 << 30), meta_size, 0);
  mprotect(meta_pool, meta_size, PROT_READ | PROT_WRITE);
  meta_nb += 1;

  // Initie un premier block a 0 pour ensuite les parcourir
  meta_pool[0].data = NULL;
  meta_pool[0].state = NONE;
  meta_pool[0].datasize = 0;
  meta_pool[0].csize = 0;
  //meta_pool[0].canary = 0;
  meta_pool[0].next = NULL;
}
void init_datapool(void) {
  void *reserved =
      mmap(NULL, (64l << 30), PROT_NONE,
           MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0); // map la pool

  data_size = 4096; // defini la size de la pool

  data_pool = (void *)mremap(
      reserved, (64l << 30), data_size,
      0); // remap pour que la pool de data soit de la taille souhaite
  mprotect(data_pool, data_size, PROT_READ | PROT_WRITE); // change les prot
  memset(data_pool, 0, data_size); // set toute la pool a 0
}

// Assigne apres avoir parcouru notre liste chainer notre block de metadata a un
// pointer vers la data
void assign_meta_block_to_data_as_free(struct metadata_t *meta_pool, void *ptr,
                                       size_t size) {
  meta_pool->state = FREE;
  meta_pool->data = ptr;
  meta_pool->datasize = size;
  meta_pool->csize = 0;
}

// Creation d'un block de metadata
struct metadata_t *add_new_metadata_block() {
  struct metadata_t *current = meta_pool;

  while (current->next != NULL) {
    current = current->next;
  }

  struct metadata_t *new_block = current + 1;

  new_block->data = NULL;
  new_block->state = NONE;
  new_block->datasize = 0;
  new_block->csize = 0;
  // new_block->canary = NULL;
  new_block->next = NULL;

  current->next = new_block;

  meta_nb++;

  return new_block;
}

struct metadata_t *check_if_a_metablock_is_free(size_t size) {
  struct metadata_t *current = meta_pool;

  while (current->next != NULL) {
    if (current->datasize >= size && current->state == FREE) {
      return current;
    }
    current = current->next;
  }
  
  if (current->datasize >= size && current->state == FREE){
    return current;
  }
  return NULL;
}

size_t get_remain_size_of_metapool(){
  size_t size_occupied = 0;
  struct metadata_t *current = meta_pool;

  while (current->next != NULL)
  {
    size_occupied += struct_size;
    current = current->next;
  }

  size_occupied += struct_size;

  return meta_size - size_occupied;
}

size_t get_remain_size_of_datapool(){
  size_t size_occupied = 0;
  struct metadata_t *current = meta_pool;

  while (current->next != NULL)
  {
    size_occupied += current->datasize;
    size_occupied += current->csize;
    current = current->next;
  }

  size_occupied += current->datasize;
  size_occupied += current->csize;

  return data_size - size_occupied;
}

void *my_malloc(size_t size) {
  // Si nos pool n'ont jamais ete allouer alors on cree nos pool
  if (meta_pool == NULL && data_pool == NULL){
    init_metapool();
    init_datapool();
  }

  // Avant d'allouer on verifie si un block est disponible pour la taille demande
  struct metadata_t *free_block = check_if_a_metablock_is_free(size);
  size_t remain_size_metapool = get_remain_size_of_metapool();
  size_t remain_size_datapool = get_remain_size_of_datapool();

  //Si oui alors on continue notre allocation
  if (free_block != NULL){
    
  }
  //Sinon on cree un nouveau bloc mais verifier avant si la taille de nos bloc depasse pas data_size et metadata_size
  else {
    if (size >= remain_size_datapool)
    {
      // Expend notre pool de data
      size_t new_data_size = data_size + (size + 512);
      if (new_data_size >= MAX_DATA_POOL_SIZE)
      {
        return NULL;
      }
      data_size = new_data_size;
    }
    if (struct_size >= remain_size_metapool)
    {
      //Expend notre pool de metadata
      size_t new_metadata_size = meta_size + (struct_size + 512);
      if (new_metadata_size >= MAX_META_POOL_SIZE)
      {
        return NULL;
      }
      meta_size = new_metadata_size;
    }
    //Cree un nouveau bloc
  }


  // Cherche un descripteur de libre
  // Si ya pas cree un nouveau bloc de metadata et on incremente
  // A chaque fois on verifie que la pool de data est assez grande sinon on
  // remap Idem pour la metadata
  (void)size;
  return NULL;
}
void my_free(void *ptr) { (void)ptr; }
void *my_calloc(size_t nmemb, size_t size) {
  (void)nmemb;
  (void)size;
  return NULL;
}

void *my_realloc(void *ptr, size_t size) {
  (void)ptr;
  (void)size;
  return NULL;
}

#ifdef DYNAMIC
void *malloc(size_t size) { return my_malloc(size); }
void free(void *ptr) { my_free(ptr); }
void *calloc(size_t nmemb, size_t size) { return my_calloc(nmemb, size); }

void *realloc(void *ptr, size_t size) { return my_realloc(ptr, size); }

#endif
