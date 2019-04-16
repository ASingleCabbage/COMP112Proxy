#ifndef DOUBLE_TABLE
#define DOUBLE_TABLE

#include <stdlib.h>
#include <stdint.h>
#include <table.h> //Good ol' Hanson; glibc has one too I think, could switch

// INVARIANT: mappings have to be one to one
typedef struct dtable *DTable;

DTable DTable_new(int hint);

void DTable_free(DTable dt);
void DTable_put(DTable dt, int clientSock, int serverSock, void *elem);
void *DTable_get(DTable dt, int sock);
void *DTable_remove(DTable dt, int clientSock, int serverSock);

// maps on the client table
void DTable_map(DTable dt, void apply(DTable dt, int clientSock, void *elem, void *cl), void *cl);

#endif /* DOUBLE_TABLE */
