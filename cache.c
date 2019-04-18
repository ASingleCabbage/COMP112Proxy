
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <table.h>
#include <atom.h>

#include "caching.h"

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
    char **urip;
    int uriLen = requestUri(req, urip);
    (void) uriLen;

    Response rsp = Table_get(csh->table, Atom_string(*urip));
    if (rsp == NULL)
        return rsp;

    int age_diff;
    int maxAge = requestHeaderValue(req, REQ_MAX_AGE);
    int maxStale = requestHeaderValue(req, REQ_MAX_STALE);
    int minFresh = requestHeaderValue(req, REQ_MIN_FRESH);
    int cacheAge = responseGetAge(rsp);
    age_diff = maxAge - (time(0) - cacheAge);

    if (minFresh > 0) {
        // if item wont be fresh for long enough
        if (age_diff <= minFresh)
            Table_remove(csh->table, Atom_string(*urip));
            return NULL;
    }
    if (maxStale > 0) {
        // if item is too stale
        if ((age_diff * -1) >= maxStale)
            Table_remove(csh->table, Atom_string(*urip));
            return NULL;
    }

    return rsp;
}

void cache_add(Cache csh, Request req, Response rsp)
{
    char **urip;
    int uriLen = requestUri(req, urip);
    (void) uriLen;
    responseSetAge(rsp, time(0));
    Table_put(csh->table, Atom_string(*urip), rsp);
}

static void print_apply(const void *key, void **value, void *cl)
{
//    Response *rsp = value;
    printf("%s\t\t%d\n", (char *) key, responseGetAge(*value));
    (void) cl;
}

void cache_list(Cache csh)
{
    printf("URL:\t\t\tAge:\n");
    Table_map(csh->table, print_apply, NULL);
    printf("End of cache\n");
}


