
#ifndef COMP112PROXY_CACHING_H
#define COMP112PROXY_CACHING_H

#include "response_parser.h"
#include "request_parser.h"


#define CACHE_LIMIT

// Use to set IP limits of DHT, when this becomes a DHT
#define CACHE_UPPER_THRESH
#define CACHE_LOWER_THRESH

typedef struct cache *Cache;

Cache cache_new();
void cache_free(Cache csh);

Response get_from_cache(Cache csh, Request req);
void cache_add(Cache csh, Request req, Response rsp);
void cache_list(Cache csh);

#endif //COMP112PROXY_CACHING_H
