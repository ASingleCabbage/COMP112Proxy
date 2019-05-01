#include <string.h>
#include <stdio.h>
#include <time.h>
#include <table.h>

#include "cache.h"
#include "hash-string.h"
#include "http_header.h"

#define BUF_SIZE 50
#define URI_LEN 2000

typedef struct cacheEntry{
    Response response;
    time_t insertionTime;
    time_t expireTime;
} *CEntry;

Cache cache_new(int hint)
{
    return Table_new(hint, (int (*)(const void *, const void *))strcmp,
                           (unsigned int (*)(const void *))string_hash);
}

void cache_free(Cache csh)
{
    /* todo map through table and free all CEntrys, but hey we probably never call this anyway */
    Table_free(&csh);
}

Response cache_get(Cache csh, Request req, int *agep)
{
    CEntry entry;
    char *uri = requestUri(req);
    if(uri == NULL){
        return NULL;
    }
    char fullPath[URI_LEN];
    if(*uri == '/'){
        /* absolute path mode, append to host */
        char *host = requestHost(req);
        int uriLen = strlen(uri);
        int hostLen = strlen(host);
        memcpy(fullPath, host, hostLen);
        memcpy(fullPath + hostLen, uri, uriLen);
        fullPath[uriLen + hostLen] = '\0';
        entry = Table_get(csh, fullPath);
        uri = fullPath;
    }else{
        entry = Table_get(csh, uri);
    }
    fprintf(stderr, "[CACHE] Cache query for %s\n", uri);

    if (entry == NULL){
        return NULL;
    }else if(entry->expireTime != 0 && entry->expireTime < time(NULL)){
        free(entry->response);
        free(entry);
        return NULL;
    }

    int age = time(NULL) - entry->insertionTime;
    if(agep != NULL){
        *agep = age;
    }

    Header ageHeader = responseHeader(entry->response, "Age");
    if(ageHeader == NULL){
        char buf[BUF_SIZE];
        sprintf(buf, "%d", age);
        responseAddHeader(entry->response, "Age", buf);
    }else{
        // free(ageHeader->value);      /* invalid free here?? */
        ageHeader->value = calloc(1, BUF_SIZE);
        sprintf(ageHeader->value, "%d", age);
    }
    fprintf(stderr, "[CACHE] Cache hit for %s\n", uri);
    return responseDuplicate(entry->response);
}

/* return value as an indicator if its freeable */
bool cache_add(Cache csh, Request req, Response rsp)
{
    if(req == NULL || rsp == NULL){
        return false;
    }
    int expiry = cache_expiry(rsp);
    if(expiry < 0){
        return false;
    }
    char *uri = requestUri(req);
    if(uri == NULL){
        return false;
    }

    CEntry entry = calloc(1, sizeof(struct cacheEntry));
    entry->insertionTime = time(NULL);
    if(expiry == 0){
        entry->expireTime = 0;
    }else{
        
        entry->expireTime = entry->insertionTime + expiry;
    }
    entry->response = responseDuplicate(rsp);

    if(*uri == '/'){
        /* absolute path mode, append to host */
        char *host = requestHost(req);
        int uriLen = strlen(uri);
        int hostLen = strlen(host);
        char *fullPath = malloc(URI_LEN);
        memcpy(fullPath, host, hostLen);
        memcpy(fullPath + hostLen, uri, uriLen);
        fullPath[uriLen + hostLen] = '\0';
        fprintf(stderr, "Inserting uri: %s, expiry at %d\n", fullPath, expiry);
        Table_put(csh, fullPath, entry);
    }else{
        char *fullPath = strdup(uri);
        strcpy(fullPath, uri);
        fprintf(stderr, "Inserting uri: %s, expiry at %d\n", fullPath, expiry);
        Table_put(csh, fullPath, entry);
    }

    return true;
}

static void remove_expired(const void *key, void **value, void *cl){
    CEntry ce = *(CEntry *)value;
    if(ce->expireTime != 0 && ce->expireTime < time(NULL)){
        responseFree(ce->response);
        free(ce);
        ce = NULL;
    }
}

void cache_pruge_expired(Cache csh){
    Table_map(csh, remove_expired, NULL);
}

/* Normally the Expire header will also be considered for expiry time, but
   ain't no one got time to parse that mess */
int cache_expiry(Response rsp){
    Header h = responseHeader(rsp, "Cache-Control");
    if(h == NULL){
        return 0;
    }
    char *controlValues = h->value;

    char *vals = malloc(strlen(controlValues) + 1);
    memcpy(vals, controlValues, strlen(controlValues) + 1);

    char *token = strsep(&vals, ","); /*whitespace may need stripping, not sure*/
    int expiry = 0;
    while(vals != NULL){
        if(strlen(token) < 1){
            break;
        }
        if(strcmp(token, "private") == 0 || strcmp(token, "no-cache") == 0 ||
           strcmp(token, "no-store") == 0){
            return -1;
        }else if(strncmp(token, "max-age", 7) == 0){
            sscanf(token, "max-age=%d", &expiry);
        }else if(strncmp(token, "s-maxage", 8) == 0){
            sscanf(token, "s-maxage=%d", &expiry);
            return expiry;
        }
        token = strsep(&vals, ",");
    }
    return expiry;
}

// static void print_apply(const void *key, void **value, void *cl)
// {
// //    Response *rsp = value;
//     printf("%s\t\t%d\n", (char *) key, responseGetAge(*value));
//     (void) cl;
// }
//
// void cache_list(Cache csh)
// {
//     printf("URL:\t\t\tAge:\n");
//     Table_map(csh, print_apply, NULL);
//     printf("End of cache\n");
// }
