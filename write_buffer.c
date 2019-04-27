#include "write_buffer.h"
#include <table.h> /* Good ol' Hanson strikes again */
#include <seq.h>

#define SEQ_HINT 20

/* The same hashing and comparison functions as DTable */
static int cmpInt(const uintptr_t a, const uintptr_t b){
    return (a < b) ? -1 : (a > b);
}

static unsigned hashWrap(const uintptr_t val){
    // Knuth's multiplicative method:
    return val * 2654435761 % 2^32;
}

WriteBuffer WBuf_new(int hint){
    return Table_new(hint, (int (*)(const void *, const void *))cmpInt, (unsigned int (*)(const void *))hashWrap);
}

/* Using Seq_T as queue, addhi remlo only*/
void WBuf_put(WriteBuffer wb, connectType type, int destSock, char *msg, int len){
    WriteEntry we = malloc(sizeof(struct writeEntry));
    we->type = type;
    we->destSock = destSock;
    we->message = msg;
    we->msgLen = len;
    Seq_T queue = Table_get(wb, (void *)(uintptr_t)destSock);
    if(queue == NULL){
        queue = Seq_new(SEQ_HINT);
        Seq_addhi(queue, we);
        Table_put(wb, (void *)(uintptr_t)destSock, queue);
    }else{
        Seq_addhi(queue, we);
    }
}

WriteEntry WBuf_get(WriteBuffer wb, int sock, int *backlogp){
    /* Table interpret 0 as NULL, which is an error state */
    if(sock == 0){
        if(backlogp != NULL){
            *backlogp = 0;
        }
        return NULL;
    }

    Seq_T queue = Table_get(wb, (void *)(uintptr_t)sock);
    if(queue == NULL || Seq_length(queue) == 0){
        if(backlogp != NULL){
            *backlogp = 0;
        }
        return NULL;
    }
    if(backlogp != NULL){
        *backlogp = Seq_length(queue) - 1;
    }
    return Seq_remlo(queue);
}

void WBuf_remove(WriteBuffer wb, int sock){
    Seq_T queue = Table_remove(wb, (void *)(uintptr_t)sock);
    if(queue == NULL){
        return;
    }
    for(int i = Seq_length(queue); i > 0; i--){
        free(Seq_remlo (queue));
    }
    Seq_free(&queue);
}
