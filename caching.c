
#include "caching.h"
#include "request_parser.h"
#include "response_parser.h"
#include <string.h>
#include <stdio.h>
#include <time.h>


struct cache {
    Table_T table;
    // more items to come - need to track size of cache, etc
};

Cache cache_new()
{
    Cache csh = malloc(sizeof(struct cache));
    csh->table = Table_new(100, NULL, NULL);
    return csh;
}

void cache_free(Cache csh)
{
    Table_free(&(csh->table));
    free(csh);
}

// Return null if item is not found, or if item is stale
// Also removes entry from table if it is stale
Response get_from_cache(Cache csh, Request req)
{
    // TODO: add procedure for no-cache validation
    Response rsp = Table_get(csh->table, Atom_string(req->uri));
    if (rsp == NULL)
        return rsp;

    int age_diff;
    age_diff = req->maxAge - (time(0) - rsp->cacheAge);
    if (req->minFresh > 0) {
        // if item wont be fresh for long enough
        if (age_diff <= req->minFresh)
            Table_remove(csh->table, Atom_string(req->uri));
            return NULL;
    }
    if (req->maxStale > 0) {
        // if item is too stale
        if ((age_diff * -1) >= req->maxStale)
            Table_remove(csh->table, Atom_string(req->uri));
            return NULL;
    }

    return rsp;
}

void cache_add(Cache csh, Request req, Response rsp)
{
    responseSetAge(rsp, time(0));
    Table_put(csh->table, Atom_string(req->uri), rsp);
}

static void print_apply(const void *key, void **value, void *cl)
{
    Response *rsp = value;
    printf("%s\t\t%s\n", key, *rsp->cacheAge);
    (void) cl;
}

void cache_list(Cache csh)
{
    printf("URL:\t\t\tAge:\n");
    Table_map(csh->table, print_apply, NULL);
    printf("End of cache\n");
}


