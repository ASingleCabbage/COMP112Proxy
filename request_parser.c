#include "request_parser.h"
#include <string.h>
#include <stdio.h>

#define FLAG_MAX_STALE      0x00000001
#define FLAG_N_CACHE        0x00000002
#define FLAG_N_STORE        0x00000004
#define FLAG_N_TRANSFORM    0x00000008
#define FLAG_ONLY_IF_CACHED 0x00000010
#define FIELD_BUFFER_SIZE 512

// TODO parse host and port (check functionality)
// host is mandatory field in HTTP 1.1?
// TODO additional parsing for content-length, to be used for msgLen (partials)

struct request{
    char *fullMsg;
    char *uri;
    char *host;
    int msgLen;
    int uriLen;
    int hostLen;
    int port;
    httpMethod method;
    int maxAge;
    int maxStale;
    int minFresh;
    char flags;
};

// basic functionality tested
// we'll do more debugging if it actually crashes ¯\_(ツ)_/¯

Request requestNew(char * message, size_t length){
    //fprintf(stderr, "Received request length %d\n %s\n", length, message);
    // fwrite(message, length, 1, stderr);
    // fprintf(stderr, "\n");

    if(length <= 0){
        return NULL;
    }

    // used for tokens
    char *msg = malloc(length + 1);
    memcpy(msg, message, length);
    msg[length] = '\0'; //making it a c string so strsep wont overflow
    char *rest = msg;
    char *token;

    Request req = calloc(1, sizeof(struct request));
    //we can just use the message and not free it after the requestNew call,
    //but I want to make it the same as request_parser (message freeable)
    req->fullMsg = malloc(length + 1);
    memcpy(req->fullMsg, message, length);
    req->fullMsg[length] = '\0';
    req->msgLen = length;

    //initialize request with proper values
    req->host = NULL;
    req->hostLen = -1;
    req->port = -1;
    req->maxAge = -1;
    req->maxStale = -1;
    req->minFresh = -1;

    token = strsep(&rest, " ");
    if(strcmp(token, "GET") == 0){
        req->method = GET;
    }else if(strcmp(token, "CONNECT") == 0){
        req->method = CONNECT;
    }else{
        fprintf(stderr, "HTTP method %s is not supported\n", token);
        return NULL;
    }

    token = strsep(&rest, " ");
    req->uriLen = strlen(token) + 1;
    req->uri = malloc(req->uriLen);
    strcpy(req->uri, token);

    char uriNoPort[FIELD_BUFFER_SIZE];
    if(sscanf(token, "%[^:]:%d", uriNoPort, &(req->port)) < 2){
        fprintf(stderr, "No port specified\n");
    }else{
        fprintf(stderr, "Port %d specified\n", req->port);
    }

    token = strsep(&rest, "\n"); /* HTTP version, dropping field */
    token = strsep(&rest, "\n");

    char buf1[FIELD_BUFFER_SIZE];
    //todo check if possible to break before reaching body
    while(token != NULL){
        if(strlen(token) == 0){
            break;
        }
        // fprintf(stderr, "TOKEN: %s\n", token);
        int startLen;
        int endLen;
        int numParsed;
        if((numParsed = sscanf(token, "Host: %n%[^:]%n:%d", &startLen, buf1, &endLen, &(req->port))) > 0){
            int bufLen;
            if(numParsed == 1){
                //probably counting the null terminator as one of the read characters
                bufLen = endLen - startLen - 1;
            }else{
                bufLen = endLen - startLen;
            }
            req->hostLen = bufLen + 1;
            req->host = malloc(req->hostLen);
            memcpy(req->host, buf1, bufLen);
            req->host[bufLen] = '\0';
        }else if(sscanf(token, "Cache-Control: %[^\n]", buf1)){
            char *rest2 = buf1;
            char *tk;
            tk = strsep(&rest2, ", ");
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
                tk = strsep(&rest2, ", ");
            }
        }
        token = strsep(&rest, "\n");
    }
    free(msg);

    return req;
}

void requestFree(Request req){
    if(req == NULL){
        return;
    }
    free(req->fullMsg);
    free(req->uri);
    free(req->host);
    free(req);
}

httpMethod requestMethod(Request req){
    return req->method;
}

size_t requestHost(Request req, char **hostp){
    *hostp = req->host;
    return req->hostLen;
}

int requestPort(Request req){
    return req->port;
}

size_t requestUri(Request req, char **urip){
    *urip = req->uri;
    return req->uriLen;
}

bool requestHasHeader(Request req, reqHeader hdr){
    switch(hdr){
        case REQ_MAX_AGE:
            return req->maxAge != -1;
        case REQ_MAX_STALE:
            return req->flags & FLAG_MAX_STALE;
        case REQ_MIN_FRESH:
            return req->minFresh != -1;
        case REQ_N_CACHE:
            return req->flags & FLAG_N_CACHE;
        case REQ_N_STORE:
            return req->flags & FLAG_N_STORE;
        case REQ_N_TRANSFORM:
            return req->flags & FLAG_N_TRANSFORM;
        case REQ_ONLY_IF_CACHED:
            return req->flags & FLAG_ONLY_IF_CACHED;
        default:
            return false;
    }
}

int requestHeaderValue(Request req, reqHeader hdr){
    switch(hdr){
        case REQ_MAX_AGE:
            return req->maxAge;
        case REQ_MAX_STALE:
            return req->maxStale;
        case REQ_MIN_FRESH:
            return req->minFresh;
        default:
            return -1;
    }
}


int requestToCharAry(Request req, char **msgp){
    *msgp = req->fullMsg;
    return req->msgLen;
}
