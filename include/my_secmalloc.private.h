#ifndef _SECMALLOC_PRIVATE_H
#define _SECMALLOC_PRIVATE_H

#include "my_secmalloc.h"
#include <stdint.h>

// sentez vous libre de modifier ce header comme vous le souhaitez
extern void *data_pool;
extern size_t meta_size;
extern size_t data_size;

enum state_t{
	NONE = 0,
	FREE = 1,
	BUSY = 2
};

struct metadata_t
{
	void *data; //Pointer vers le block data
	enum state_t state; //Etat du block de metadata
	//size_t size; //Taille du block de metadata
	size_t datasize; //Taille du block de data vers lequel il pointe si alloue uniquement
	size_t csize; //Taille du canary dans le block
	unsigned char canary[32]; //TODO: Gestion de l'alignement
	struct metadata_t *next;
	struct metadata_t *prev;
};


void init_metapool(void);
void init_datapool(void);

void assign_meta_block_to_data_as_free(struct metadata_t *, void *ptr, size_t);

struct metadata_t *add_new_metadata_block();
struct metadata_t *check_if_a_metablock_is_free(size_t);

size_t get_remain_size_of_metapool();
size_t get_remain_size_of_datapool();

void *search_where_data_block_pointer_is();

uint8_t check_size_of_pool_and_extend(size_t);

uint8_t detect_free_space_in_datapool(size_t, struct metadata_t *);

struct metadata_t *find_metablock_associated_to_datablock(void *);

void    *my_malloc(size_t size);
void    my_free(void *ptr);
void    *my_calloc(size_t nmemb, size_t size);
void    *my_realloc(void *ptr, size_t size);

#endif
