#include <string.h>
#include <stdio.h>
#include <time.h>
#include <table.h>

#include "cache.h"
#include "hash-string.h"
#include "response_parser_dynamic.h"


#define BUF_SIZE 50

typedef struct cacheEntry{
    Response response;
    time_t insertionTime;
    time_t expireTime;
} *CEntry;

Cache cache_new(int hint)
{
    return Table_new(hint, strcmp, string_hash);
}

void cache_free(Cache csh)
{
    /* todo map through table and free all CEntrys, but hey we probably never call this anyway */
    Table_free(&csh);
}

Response cache_get(Cache csh, char *uri, int *agep)
{
    CEntry entry = Table_get(csh, uri);
    if (entry == NULL){
        return NULL;
    }else if(entry->expireTime < time(NULL)){
        free(entry->response);
        free(entry);
        return NULL;
    }

    int age = time(NULL) - entry->insertionTime;

    if(agep != NULL){
        *agep = age;
    }

    Header ageHeader = reponseHeader(entry->response, "Age");
    if(ageHeader == NULL){
        char buf[BUF_SIZE];
        sprintf(buf, "%d", age);
        responseAddHeader(entry->response, "Age", buf);
    }else{
        free(ageHeader->value);
        ageHeader->value = calloc(1, BUF_SIZE);
        sprintf(ageHeader->value, "%d", age);
    }
    return entry->response;
}

bool cache_add(Cache csh, char *uri, Response rsp)
{
    int expiry = cache_expiry(rsp);
    if(expiry < 0){
        return false;
    }

    CEntry entry = malloc(sizeof(struct cacheEntry));
    entry->insertionTime = time(NULL);
    entry->expireTime = entry->insertionTime + expiry;
    entry->response = rsp;

    Table_put(csh, uri, entry);
    return true;
}

static void remove_expired(const void *key, void **value, void *cl){
    CEntry ce = *(CEntry *)value;
    if(ce->expireTime < time(NULL)){
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
    char *controlValues = responseHeader(rsp, "Cache-Control");
    if(controlValues == NULL){
        return 0;
    }

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
        char *token = strsep(&vals, ",");
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
