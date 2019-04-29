#ifndef COMP112PROXY_CACHING_H
#define COMP112PROXY_CACHING_H

#include "table.h"
#include "response_parser_dynamic.h"
#include "request_parser_dynamic.h"
#include <stdbool.h>

typedef Table_T Cache;

Cache cache_new(int hint);
void cache_free(Cache csh);

Response cache_get(Cache csh, Request req, int *agep);
bool cache_add(Cache csh, Request req, Response rsp);
void cache_pruge_expired(Cache csh);

// void cache_list(Cache csh);

/* returns 0 for infinite, -1 for non-cacheables, and > 0 for those with expiry time set */
int cache_expiry(Response rsp);

#endif //COMP112PROXY_CACHING_H
