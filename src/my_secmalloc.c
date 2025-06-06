#define _GNU_SOURCE
#include "../include/my_secmalloc.private.h"
#include <alloca.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define MAX_META_POOL_SIZE (1 << 30)
#define MAX_DATA_POOL_SIZE (64l << 30)
#define CANARY_SIZE 32

size_t struct_size = sizeof(struct metadata_t);
void *data_pool = NULL;
size_t meta_size = 0;
size_t data_size = 0;
struct metadata_t *meta_pool = NULL;
size_t meta_nb = 0;
struct metadata_t *meta_pool_addr = NULL;
size_t offset_metadata = 0;

#include <stdint.h>
#include <unistd.h>

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

uint8_t gen_canary(unsigned char buffer[CANARY_SIZE]) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return 1;
  }

  ssize_t bytes_read = read(fd, buffer, CANARY_SIZE);
  close(fd);

  if (bytes_read != CANARY_SIZE) {
    return 1;
  }

  return 0;
}

void init_metapool(void) {
  void *reserved = mmap(NULL, (1 << 30), PROT_NONE,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1,
                        0); // A changer la prot

  meta_size = 4096;

  meta_pool = (struct metadata_t *)mremap(reserved, (1 << 30), meta_size, 0);
  meta_pool_addr = meta_pool;
  mprotect(meta_pool, meta_size, PROT_READ | PROT_WRITE);
  meta_nb += 1;

  // Initie un premier block a 0 pour ensuite les parcourir
  meta_pool->data = NULL;
  // meta_pool->state = NONE;
  meta_pool->datasize = 0;
  meta_pool->csize = CANARY_SIZE;
  // meta_pool[0].canary = 0;
  meta_pool->next = NULL;
  meta_pool->prev = NULL;
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

// Creation d'un block de metadata
struct metadata_t *add_new_metadata_block() {
  struct metadata_t *current = meta_pool_addr;
  struct metadata_t *prev = NULL;
  while (current->next != NULL) {
    prev = current;
    current = current->next;
  }

  if ((meta_nb + 1) * struct_size > meta_size){
    return NULL;
  }

  struct metadata_t *new_block = meta_pool + meta_nb;
  current->next = new_block;
  current->prev = prev;

  new_block->data = NULL;
  // new_block->state = NONE;
  new_block->datasize = 0;
  new_block->csize = CANARY_SIZE;
  // new_block->canary = NULL;
  new_block->next = NULL;
  new_block->prev = current;

  meta_nb++;

  return new_block;
}

struct metadata_t *allocate_new_metadatablock() {

  struct metadata_t *new = meta_pool + meta_nb;
  meta_nb++;

  return new;
}

uint8_t detect_free_space_in_datapool(size_t size, struct metadata_t *current) {

  size_t available = 0;
  // Dans le cas ou on est au milieu pas a la fin
  if (current->next != NULL) {
    available = (current->next->data) -
                (current->data + current->datasize + current->csize);
  }
  // Check si le premier a pas etait free;
  if (current->prev == NULL && current != meta_pool) {
    available = current->data - data_pool;
    // Si superieur a 0 notre current n'est pas vraiment le premier bloc et on
    // check si la taille demande peut etre contenu
  }
  if (available != 0 && available >= size + CANARY_SIZE) {
    return 1;
  }
  return 0;
}

size_t align_size(size_t size) { return (size + 7) & ~7; }

struct metadata_t *check_if_a_metablock_is_free(size_t size) {
  struct metadata_t *current = meta_pool_addr;

  // Si c'est le premier bloc on verifie que se soit pas un pseudo premier
  if (current->prev == NULL && current->data > data_pool) {
    if (detect_free_space_in_datapool(size, current)) {
      meta_pool->csize = CANARY_SIZE;
      meta_pool->datasize = size;
      meta_pool->next = current;
      meta_pool->prev = current->prev;
      meta_pool->data = data_pool;

      current->prev = meta_pool;

      meta_pool_addr = meta_pool;

      return meta_pool;
    }
  }

  // Si c'est pas le premier on parcours
  while (current->next != NULL) {
    // printf("next next %p %p\n", current->next->next,
    // current->next->next->data);
    if (detect_free_space_in_datapool(size, current)) {
      // Cree un nouveau bloc de meta data pointant vers l'espace free
      struct metadata_t *new = allocate_new_metadatablock();
      new->csize = CANARY_SIZE;
      new->datasize = size;
      new->next = current->next;
      new->prev = current;
      new->data = current->data + current->datasize + current->csize;
      current->next = new;

      return new;
    }
    current = current->next;
  }
  return NULL;
}

size_t get_remain_size_of_metapool() {
  size_t size_occupied = 0;

  size_occupied = struct_size * meta_nb;

  // write(1, "--------\n", 9);
  // write(1, "SIZE OF METAPOOL ", 17);
  // print_size_t(meta_size - size_occupied);
  // write(1, "\n", 1);
  // write(1, "--------\n", 9);

  return meta_size - size_occupied;
}

size_t get_remain_size_of_datapool() {
  size_t size_occupied = 0;
  struct metadata_t *current = meta_pool_addr;

  while (current->next != NULL) {
    size_occupied += current->datasize;
    size_occupied += current->csize;
    current = current->next;
  }

  size_occupied += current->datasize;
  size_occupied += current->csize;

  // write(1, "--------\n", 9);
  // write(1, "SIZE OF DATAPOOL ", 17);
  // print_size_t(data_size - size_occupied);
  // write(1, "\n", 1);
  // write(1, "--------\n", 9);

  return data_size - size_occupied;
}

void *search_where_data_block_pointer_is() {
  struct metadata_t *current = meta_pool_addr;
  size_t step = 0;
  void *ptr;
  void *pointer_to_data_block;
  while (current->next != NULL) {
    current = current->next;
  }
  ptr = current->prev->data;
  step = current->prev->datasize + current->prev->csize;

  pointer_to_data_block = ptr + step;

  return pointer_to_data_block;
}

uint8_t check_size_of_pool_and_extend(size_t size) {
  size_t remain_size_metapool = get_remain_size_of_metapool();
  size_t remain_size_datapool = get_remain_size_of_datapool();
  if (size >= remain_size_datapool) {
    // Expend notre pool de data
    size_t new_data_size = data_size + (size + 51200);
    if (new_data_size >= MAX_DATA_POOL_SIZE) {
      return 1;
    }
    // remap
    void *new_data_pool =
        (void *)mremap(data_pool, data_size, new_data_size, 0);
    if (new_data_pool == NULL) {
      return 1;
    }

    data_size = new_data_size; // Redefini la size pour les prochain appel
    data_pool = new_data_pool; // Redefini la pool pour les prochain appel
  }
  if (struct_size >= remain_size_metapool) {
    // Expend notre pool de metadata
    size_t new_metadata_size = meta_size + (struct_size + 51200);
    if (new_metadata_size >= MAX_META_POOL_SIZE) {
      return 1;
    }
    // remap
    struct metadata_t *new_metadata_pool =
        (struct metadata_t *)mremap(meta_pool, meta_size, new_metadata_size, 0);
    if (new_metadata_pool == NULL) {
      return 1;
    }

    meta_size = new_metadata_size;
    meta_pool = new_metadata_pool;
    meta_pool_addr = meta_pool;
  }

  return 0;
}

struct metadata_t *find_metablock_associated_to_datablock(void *ptr) {
  struct metadata_t *current = meta_pool_addr;

  while (current->next != NULL) {
    if (current->data == ptr) {
      if (memcmp(ptr + current->datasize, current->canary, CANARY_SIZE) != 0) {
        abort();
      }
      return current;
    }
    current = current->next;
  }
  // Check si c'est pas le dernier bloc
  if (current->data == ptr) {
    if (memcmp(ptr + current->datasize, current->canary, CANARY_SIZE) != 0) {
      abort();
    }
    return current;
  }

  return NULL;
}

void *my_malloc(size_t size) {

  if (size == 0) {
    return NULL;
  }

  size = align_size(size);
  // Si nos pool n'ont jamais ete init alors on cree nos pool et on alloue les
  // premiers bloc a notre malloc
  if (meta_pool == NULL && data_pool == NULL) {
    init_metapool();
    init_datapool();

    uint8_t res = check_size_of_pool_and_extend(size);
    if (res == 1) {
      return NULL;
    }

    meta_pool->data = data_pool;
    // meta_pool->state = BUSY;
    meta_pool->datasize = size;

    // TODO canary
    gen_canary(meta_pool->canary);
    memcpy(data_pool + meta_pool->datasize, meta_pool->canary, CANARY_SIZE);

    return data_pool;
  }

  // Avant d'allouer on verifie si un block est disponible pour la taille
  // demande
  struct metadata_t *free_block = check_if_a_metablock_is_free(size);

  // Si oui alors on continue notre allocation
  // Sinon on cree un nouveau bloc mais verifier avant si la taille de nos bloc
  // depasse pas data_size et metadata_size
  if (free_block == NULL) {
    //   write(1, "Ajout de bloc\n", 14);
    uint8_t res = check_size_of_pool_and_extend(size);
    if (res == 1) {
      //    write(1, "GROS\n", 5);
      return NULL;
    }

    // Cree un nouveau bloc
    struct metadata_t *new_block = add_new_metadata_block();
    // Chercher ou se trouve notre bloc de data associer
    void *data_block = search_where_data_block_pointer_is();
    new_block->datasize = size;
    // new_block->state = BUSY;
    new_block->data = data_block;
    // TODO Ajouter le canary
    gen_canary(new_block->canary);
    memcpy(data_block + new_block->datasize, new_block->canary, CANARY_SIZE);

    return data_block;
  }

  // free_block->state = BUSY;
  free_block->datasize = size;

  // TODO Ajoute le canary
  gen_canary(free_block->canary);
  memcpy(free_block->data + free_block->datasize, free_block->canary,
         CANARY_SIZE);

  return free_block->data;
}

void my_free(void *ptr) {
  struct metadata_t *current = meta_pool_addr;

  while (current->next != NULL) {
    if (current->data == ptr) {
      if (memcmp(ptr + current->datasize, current->canary, CANARY_SIZE) != 0) {
        abort();
      }
      if (current == meta_pool_addr) { // Si c'est le premier bloc
        current->next->prev =
            current->prev; // Alors on set le next en pseudo premier bloc
        meta_pool_addr = current->next;
      } else { // Si c'est un bloc au milieu alors on on link celui d'avant avec
               // celui d'apres
        current->prev->next = current->next;
        current->next->prev = current->prev;
      }
      memset(ptr, 0, current->datasize + CANARY_SIZE);
      memset(current, 0, sizeof(struct metadata_t));
      break;
    }
    current = current->next;
  }

  // Si on est a la fin
  if (current->next == NULL && current->prev != NULL && current->data == ptr) {
    current->prev->next = current->next;
    memset(ptr, 0, current->datasize + CANARY_SIZE);
    memset(current, 0, sizeof(struct metadata_t));
  }
  // Si tout est free meme le dernier bloc
  if (current->next == NULL && current->prev == NULL && current->data == ptr) {
    memset(ptr, 0, current->datasize + CANARY_SIZE);
    memset(current, 0, sizeof(struct metadata_t));
    meta_pool_addr = meta_pool;
    meta_pool->data = data_pool;
  }
}

void *my_calloc(size_t nmemb, size_t size) {
  if (size != 0 && nmemb > SIZE_MAX / size) {
    return NULL;
  }
  size_t total = nmemb * size;
  void *ptr = my_malloc(total);
  if (ptr) {
    memset(ptr, 0, total);
    return ptr;
  }

  return NULL;
}

void *my_realloc(void *ptr, size_t size) {
  if (ptr == NULL) {
    return my_malloc(size);
  }
  if (ptr != NULL && size == 0) {
    return NULL;
  }

  size = align_size(size);
  // Trouver le bloc
  struct metadata_t *find_block = find_metablock_associated_to_datablock(ptr);
  if (find_block != NULL) {
    // Fait notre realloc
    if (size <= find_block->datasize) {
      // Reduit notre datablock
      find_block->datasize = size;

      // Deplacer le canary
      void *canary_pos = find_block->data + find_block->datasize;
      memcpy(canary_pos, find_block->canary, CANARY_SIZE);

      return find_block->data;
    }
    if (size >= find_block->datasize) {
      // Si notre bloc est a la fin
      if (find_block->next == NULL) {
        uint8_t res = check_size_of_pool_and_extend(size);
        if (res == 1) {
          return NULL;
        }
        find_block->datasize = size;
        void *canary_pos = find_block->data + find_block->datasize;
        memcpy(canary_pos, find_block->canary, CANARY_SIZE);

        return find_block->data;
      } else {
        size_t available =
            (find_block->next->data) -
            (find_block->data + find_block->datasize + find_block->csize);
        if (available >= (size - find_block->datasize)) {
          // Etend
          find_block->datasize = size;
          void *canary_pos = find_block->data + find_block->datasize;
          memcpy(canary_pos, find_block->canary, CANARY_SIZE);

          return find_block->data;
        }
        // Si pas d'espace free on free le bloc actuel et on cree un nouveau
        // bloc
        else {
          void *new_data_block = my_malloc(size);
          if (new_data_block == NULL) {
            return NULL;
          }
          // Copie les data mais pas le canary car cree auto avec le malloc
          memcpy(new_data_block, find_block->data, find_block->datasize);
          my_free(find_block->data);

          return new_data_block;
        }
      }
    }
  }

  return NULL;
}

#ifdef DYNAMIC
void *malloc(size_t size) { return my_malloc(size); }
void free(void *ptr) { my_free(ptr); }
void *calloc(size_t nmemb, size_t size) { return my_calloc(nmemb, size); }

void *realloc(void *ptr, size_t size) { return my_realloc(ptr, size); }

#endif
