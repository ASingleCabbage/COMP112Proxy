#ifndef DOUBLE_TABLE
#define DOUBLE_TABLE

#include <stdlib.h>
#include <stdint.h>
#include <table.h> //Good ol' Hanson; glibc has one too I think, could switch

// #pragma GCC system_header
// #include "lookup3.c"

typedef struct dtable *DTable;

/* Doubly mapped table, integer types only (?) */

DTable DTable_new(int hint);

void  DTable_free(DTable dt);
void DTable_put(DTable dt, uintptr_t key1, uintptr_t key2);
int DTable_get(DTable dt, uintptr_t key);
void DTable_remove(DTable dt, uintptr_t key);

#endif /* DOUBLE_TABLE */
