#include "request_parser.h"
#include <string.h>
#include <stdio.h>

#define FLAG_MAX_STALE      0x00000001
#define FLAG_N_CACHE        0x00000002
#define FLAG_N_STORE        0x00000004
#define FLAG_N_TRANSFORM    0x00000008
#define FLAG_ONLY_IF_CACHED 0x00000010
// #define FLAG_MUST_REVAL     0x00000020
// #define FLAG_PUBLIC         0x00000040
// #define FLAG_PRIVATE        0x00000080
// #define FLAG_PROXY_REVAL    0x00000100
#define FIELD_BUFFER_SIZE 50

struct request{
    httpMethod method;
    char *uri;
    char *host;
    int uriLen;
    int hostLen;
    int maxAge;
    int maxStale;
    int minFresh;
    char flags;
};

// todo unit tests required

Request requestNew(char * message, size_t length){
    char *sp;
    Request req = calloc(1, sizeof(struct request));
    char *token;

    //initialize request with proper values
    req->host = NULL;
    req->hostLen = -1;
    req->maxAge = -1;
    req->maxStale = -1;
    req->minFresh = -1;

    token = strtok_r(message, " ", &sp);
    if(strcmp(token, "GET") == 0){
        req->method = GET;
    }else if(strcmp(token, "CONNECT") == 0){
        req->method = CONNECT;
    }else{
        fprintf(stderr, "HTTP method %s is not supported\n", token);
        return NULL;
    }

    token = strtok_r(NULL, " ", &sp);
    req->uriLen = strlen(token);
    req->uri = malloc(req->uriLen);
    strcpy(req->uri, token);

    token = strtok_r(NULL, "/n", &sp); /* HTTP version, dropping field */
    token = strtok_r(NULL, "/n", &sp);

    char buf1[FIELD_BUFFER_SIZE];
    while(token != NULL){
        if(sscanf(token, "Host: %s", buf1) == 1){
            req->hostLen = strlen(buf1);
            req->host = malloc(req->hostLen);
            strcpy(req->uri, buf1);
        }else if(sscanf(token, "Cache-Control: %[^\n]", buf1)){
            char *sp2;
            char *tk;
            tk = strtok_r(buf1, ", ", &sp2);
            while(tk != NULL){
                if(strcmp(tk, "no-cache") == 0){
                    req->flags &= FLAG_N_CACHE;
                }else if(strcmp(tk, "no-store") == 0){
                    req->flags &= FLAG_N_STORE;
                }else if(strcmp(tk, "no-transform") == 0){
                    req->flags &= FLAG_N_TRANSFORM;
                }else if(strcmp(tk, "only-if-cached") == 0){
                    req->flags &= FLAG_ONLY_IF_CACHED;
                }else if(strncmp(tk, "max-age=", 8) == 0){
                    req->maxAge = strtol(tk + 8, NULL, 10);
                }else if(strncmp(tk, "max-stale", 9) == 0){
                    req->flags &= FLAG_MAX_STALE;
                    if(strlen(tk) > 9){
                        req->maxStale = strtol(tk + 9, NULL, 10);
                    }
                }else if(strncmp(tk, "min-fresh=", 10) == 0){
                    req->minFresh = strtol(tk + 10, NULL, 10);
                }
                tk = strtok_r(NULL, ", ", &sp2);
            }
        }
    }

    return req;
}

void requestFree(Request req){
    if(req == NULL){
        return;
    }
    free(req->uri);
    free(req->host);
    free(req);
}

int requestHost(Request req, char **hostp){
    *hostp = req->host;
    return req->hostLen;
}

int requestUri(Request req, char **urip){
    *urip = req->uri;
    return req->uriLen;
}

bool requestHasHeader(Request req, reqHeader hdr){
    switch(hdr){
        case MAX_AGE:
            return req->maxAge != -1;
        case MAX_STALE:
            return req->flags & FLAG_MAX_STALE;
        case MIN_FRESH:
            return req->minFresh != -1;
        case N_CACHE:
            return req->flags & FLAG_N_CACHE;
        case N_STORE:
            return req->flags & FLAG_N_STORE;
        case N_TRANSFORM:
            return req->flags & FLAG_N_TRANSFORM;
        case ONLY_IF_CACHED:
            return req->flags & FLAG_ONLY_IF_CACHED;
    }
}

int requestHeaderValue(Request req, reqHeader hdr){
    switch(hdr){
        case MAX_AGE:
            return req->maxAge;
        case MAX_STALE:
            return req->maxStale;
        case MIN_FRESH:
            return req->minFresh;
        default:
            return -1;
    }
}
