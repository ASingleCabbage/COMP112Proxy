#include "double_table.h"
#include <table.h>
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>

struct dtable{
    Table_T clientT;
    Table_T serverT;
};

/* since Table_T requires (void *) as key, we use uintptr_ts and store by value */

static int cmpInt(const uintptr_t a, const uintptr_t b){
    return (a < b) ? -1 : (a > b);
}

static unsigned hashWrap(const uintptr_t val){
    // Knuth's multiplicative method:
    return val * 2654435761 % 2^32;
}

DTable DTable_new(int hint){
    DTable dt = malloc(sizeof(struct dtable));
    dt->clientT = Table_new(hint, (int (*)(const void *, const void *))cmpInt, (unsigned int (*)(const void *))hashWrap);
    dt->serverT = Table_new(hint, (int (*)(const void *, const void *))cmpInt, (unsigned int (*)(const void *))hashWrap);
    return dt;
}

void DTable_free(DTable dt){
    Table_free(&(dt->clientT));
    Table_free(&(dt->serverT));
    free(dt);
}

void DTable_put(DTable dt, int clientSock, int serverSock, void *elem){
    void *v1 = Table_put(dt->clientT, (void *)(uintptr_t)clientSock, (void *)elem);
    assert(v1 == NULL);
    void *v2 = Table_put(dt->serverT, (void *)(uintptr_t)serverSock, (void *)elem);
    assert(v2 == NULL);
}

void *DTable_get(DTable dt, int sock){
    void *val = Table_get(dt->clientT, (void *)(uintptr_t)sock);
    if(val == NULL){
        val = Table_get(dt->serverT, (void *)(uintptr_t)sock);
    }
    return val;
}

void *DTable_remove(DTable dt, int clientSock, int serverSock){
    void *val = Table_remove(dt->clientT, (void *)(uintptr_t)clientSock);
    if(val == NULL){
        Table_remove(dt->clientT, (void *)(uintptr_t)serverSock);
        val = Table_remove(dt->serverT, (void *)(uintptr_t)clientSock);
        return val;
    }
    Table_remove(dt->serverT, (void *)(uintptr_t)serverSock);
    return val;
}
