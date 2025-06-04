// Corrections pour my_secmalloc.c

// Fonction utilitaire pour aligner la taille
static size_t align_size(size_t size) {
    // Alignement sur 8 bytes minimum
    return (size + 7) & ~7;
}

// Version corrigée de detect_free_space_in_datapool
uint8_t detect_free_space_in_datapool(size_t size, struct metadata_t *current) {
    size_t available = 0;
    
    // Si ce n'est pas un bloc initialisé, ignorer
    if (current->state == NONE && current->data == NULL) {
        return 0;
    }
    
    // Si le bloc est occupé, pas libre
    if (current->state == BUSY) {
        return 0;
    }
    
    // Cas 1: Il y a un bloc suivant
    if (current->next != NULL) {
        available = (char*)current->next->data - 
                   ((char*)current->data + current->datasize + current->csize);
    }
    // Cas 2: C'est le dernier bloc, calculer l'espace jusqu'à la fin de la pool
    else {
        available = ((char*)data_pool + data_size) - 
                   ((char*)current->data + current->datasize + current->csize);
    }
    
    // Cas 3: Début de la pool libre
    if (current->prev == NULL && current->data > data_pool) {
        available = (char*)current->data - (char*)data_pool;
    }
    
    return (available >= align_size(size) + CANARY_SIZE);
}

// Version complètement réécrite de check_if_a_metablock_is_free
struct metadata_t *check_if_a_metablock_is_free(size_t size) {
    size_t aligned_size = align_size(size);
    struct metadata_t *current = meta_pool_addr;
    
    // Cas spécial: première allocation dans une pool vide
    if (current->data == NULL && current->state == NONE) {
        current->data = data_pool;
        current->datasize = aligned_size;
        current->state = BUSY;
        current->csize = CANARY_SIZE;
        return current;
    }
    
    // Parcourir tous les blocs pour trouver un FREE ou un espace libre
    while (current != NULL) {
        // Bloc explicitement FREE
        if (current->state == FREE && current->datasize >= aligned_size) {
            current->state = BUSY;
            current->datasize = aligned_size;
            return current;
        }
        
        // Chercher de l'espace libre avant ce bloc
        if (current->prev == NULL && current->data > data_pool) {
            size_t space_before = (char*)current->data - (char*)data_pool;
            if (space_before >= aligned_size + CANARY_SIZE) {
                // Créer un nouveau bloc au début
                struct metadata_t *new_block = add_new_metadata_block();
                if (!new_block) return NULL;
                
                new_block->data = data_pool;
                new_block->datasize = aligned_size;
                new_block->state = BUSY;
                new_block->csize = CANARY_SIZE;
                
                // Insérer au début de la liste
                new_block->next = current;
                new_block->prev = NULL;
                current->prev = new_block;
                meta_pool_addr = new_block;
                
                return new_block;
            }
        }
        
        // Chercher de l'espace libre entre ce bloc et le suivant
        if (current->next != NULL) {
            char *end_current = (char*)current->data + current->datasize + current->csize;
            char *start_next = (char*)current->next->data;
            size_t space_between = start_next - end_current;
            
            if (space_between >= aligned_size + CANARY_SIZE) {
                // Créer un nouveau bloc dans l'espace libre
                struct metadata_t *new_block = add_new_metadata_block();
                if (!new_block) return NULL;
                
                new_block->data = (void*)end_current;
                new_block->datasize = aligned_size;
                new_block->state = BUSY;
                new_block->csize = CANARY_SIZE;
                
                // Insérer dans la liste
                new_block->next = current->next;
                new_block->prev = current;
                current->next->prev = new_block;
                current->next = new_block;
                
                return new_block;
            }
        }
        
        current = current->next;
    }
    
    return NULL; // Aucun espace libre trouvé
}

// Version corrigée de my_free
void my_free(void *ptr) {
    if (ptr == NULL) return;
    
    struct metadata_t *current = meta_pool_addr;
    
    // Trouver le bloc correspondant
    while (current != NULL) {
        if (current->data == ptr) {
            // Vérifier l'intégrité du canary avant de libérer
            char *canary_pos = (char*)ptr + current->datasize;
            if (memcmp(canary_pos, current->canary, CANARY_SIZE) != 0) {
                fprintf(stderr, "CORRUPTION DETECTED: Canary mismatch!\n");
                abort();
            }
            
            // Marquer comme libre au lieu de supprimer
            current->state = FREE;
            
            // Effacer les données pour la sécurité
            memset(ptr, 0, current->datasize);
            
            // Tentative de fusion avec les blocs adjacents libres
            // Fusion avec le bloc suivant
            if (current->next && current->next->state == FREE) {
                char *end_current = (char*)current->data + current->datasize + current->csize;
                if (end_current == (char*)current->next->data) {
                    current->datasize += current->next->datasize + current->next->csize;
                    struct metadata_t *to_remove = current->next;
                    current->next = to_remove->next;
                    if (to_remove->next) {
                        to_remove->next->prev = current;
                    }
                    memset(to_remove, 0, sizeof(struct metadata_t));
                    meta_nb--;
                }
            }
            
            // Fusion avec le bloc précédent
            if (current->prev && current->prev->state == FREE) {
                char *end_prev = (char*)current->prev->data + current->prev->datasize + current->prev->csize;
                if (end_prev == (char*)current->data) {
                    current->prev->datasize += current->datasize + current->csize;
                    current->prev->next = current->next;
                    if (current->next) {
                        current->next->prev = current->prev;
                    }
                    if (current == meta_pool_addr) {
                        meta_pool_addr = current->prev;
                    }
                    memset(current, 0, sizeof(struct metadata_t));
                    meta_nb--;
                }
            }
            
            return;
        }
        current = current->next;
    }
    
    // Si on arrive ici, le pointeur n'a pas été trouvé
    fprintf(stderr, "INVALID FREE: Pointer not found!\n");
}

// Version corrigée de my_malloc
void *my_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    size_t aligned_size = align_size(size);
    
    // Initialisation des pools si nécessaire
    if (meta_pool == NULL && data_pool == NULL) {
        init_metapool();
        init_datapool();
        
        meta_pool->data = data_pool;
        meta_pool->state = BUSY;
        meta_pool->datasize = aligned_size;
        meta_pool->csize = CANARY_SIZE;
        
        // Générer et placer le canary
        if (gen_canary(meta_pool->canary) != 0) {
            return NULL;
        }
        memcpy((char*)data_pool + aligned_size, meta_pool->canary, CANARY_SIZE);
        
        return data_pool;
    }
    
    // Chercher un bloc libre existant
    struct metadata_t *free_block = check_if_a_metablock_is_free(aligned_size);
    
    if (free_block == NULL) {
        // Vérifier si on peut étendre les pools
        if (check_size_of_pool_and_extend(aligned_size) != 0) {
            return NULL;
        }
        
        // Créer un nouveau bloc à la fin
        struct metadata_t *new_block = add_new_metadata_block();
        if (new_block == NULL) {
            return NULL;
        }
        
        // Trouver l'emplacement pour les données
        void *data_location = search_where_data_block_pointer_is();
        
        new_block->data = data_location;
        new_block->datasize = aligned_size;
        new_block->state = BUSY;
        new_block->csize = CANARY_SIZE;
        
        // Générer et placer le canary
        if (gen_canary(new_block->canary) != 0) {
            return NULL;
        }
        memcpy((char*)data_location + aligned_size, new_block->canary, CANARY_SIZE);
        
        return data_location;
    }
    
    // Utiliser le bloc libre trouvé
    free_block->state = BUSY;
    free_block->datasize = aligned_size;
    
    // Générer et placer le canary
    if (gen_canary(free_block->canary) != 0) {
        return NULL;
    }
    memcpy((char*)free_block->data + aligned_size, free_block->canary, CANARY_SIZE);
    
    return free_block->data;
}