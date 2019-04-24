#include "response_parser.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FLAG_N_CACHE        0x00000001
#define FLAG_N_STORE        0x00000002
#define FLAG_N_TRANSFORM    0x00000004
#define FLAG_MUST_REVAL     0x00000008
#define FLAG_PUBLIC         0x00000010
#define FLAG_PRIVATE        0x00000020
#define FLAG_PROXY_REVAL    0x00000040
#define FIELD_BUFFER_SIZE 50

//seperate type for response
struct response{
    char *head;
    char *body;
    int contentLen;
    int headLen;
    int bodyLen;
    int status;
    int maxAge;
    int sMaxAge;
    int cacheAge;
    char flags;
};

struct sResponse{
    char *msg;
    int len;
};

SResponse responseNewS(char *message, size_t length){
    SResponse srsp = malloc(length);
    srsp->msg = malloc(length);
    memcpy(srsp->msg, message, length);
    srsp->len = length;
    return srsp;
}

void responseFreeS(SResponse srsp){
    free(srsp->msg);
    free(srsp);
}

// TODO cannot handle case where message header already contains age
// on second thought would this be an issue though? ¯\_(ツ)_/¯
Response responseNew(char * message, size_t length){
    if(length <= 0){
        return NULL;
    }

    char *msg = calloc(1, length);
    memcpy(msg, message, length);
    char *rest = msg;
    char *token;
    Response rsp = calloc(1, sizeof(struct response));

    rsp->contentLen = -1;
    rsp->maxAge = -1;
    rsp->sMaxAge = -1;

    token = strsep(&rest, " "); /* HTTP Version */
    token = strsep(&rest, " ");
    rsp->status = strtol(token, NULL, 10);
    token = strsep(&rest, "\n"); /* Reason Phrase */

    token = strsep(&rest, "\n");
    char buf1[FIELD_BUFFER_SIZE];
    int num1;
    while(token != NULL){
        if(strlen(token) <= 1){
            break;
        }
        // printf("Token (%d):%s\n", strlen(token), token);
        if(sscanf(token, "Cache-Control: %[^\n]", buf1)){
            // printf("%s\n", "[IDENTIFIED CACHE CONTROL]\n");
            char *br = buf1;
            char *tk;
            tk = strsep(&br, " ");
            while(tk != NULL){
                if(strncmp(tk, "must-revalidate", 15) == 0){
                    rsp->flags &= FLAG_MUST_REVAL;
                }else if(strncmp(tk, "no-cache", 8) == 0){
                    rsp->flags &= FLAG_N_CACHE;
                }else if(strncmp(tk, "no-store", 8) == 0){
                    rsp->flags &= FLAG_N_STORE;
                }else if(strncmp(tk, "no-transform", 12) == 0){
                    rsp->flags &= FLAG_N_TRANSFORM;
                }else if(strncmp(tk, "public", 6) == 0){
                    rsp->flags &= FLAG_PUBLIC;
                }else if(strncmp(tk, "private", 7) == 0){
                    rsp->flags &= FLAG_PRIVATE;
                }else if(strncmp(tk, "proxy-revalidate", 16) == 0){
                    rsp->flags &= FLAG_PROXY_REVAL;
                }else if(strncmp(tk, "max-age=", 8) == 0){
                    rsp->maxAge = strtol(tk + 8, NULL, 10);
                    // printf("Max age %s, %d\n", tk+8, rsp->maxAge);
                }else if(strncmp(tk, "s-maxage=", 9) == 0){
                    rsp->sMaxAge = strtol(tk + 9, NULL, 10);
                }
                tk = strsep(&br, " ");
            }
        }else if(sscanf(token, "Content-Length: %d", &num1)){
            rsp->contentLen = num1;
        }
        token = strsep(&rest, "\n");
    }
    rsp->headLen = token - msg;
    rsp->head = calloc(1, rsp->headLen);
    memcpy(rsp->head, message, rsp->headLen);

    rsp->bodyLen = length - rsp->headLen - 2;
    rsp->body = calloc(1, rsp->bodyLen);

    // printf("remaining length %d\n", rsp->bodyLen);
    // printf("%s\n", rest);

    memcpy(rsp->body, rest, rsp->bodyLen);

    free(msg);
    return rsp;
}

void responseFree(Response rsp){
    if(rsp == NULL){
        return;
    }
    free(rsp->head);
    free(rsp->body);
    free(rsp);
}

int responseStatus(Response rsp){
    return rsp->status;
}

bool responseHasHeader(Response rsp, rspHeader hdr){
    switch(hdr){
        case RSP_MAX_AGE:
            return rsp->maxAge != -1;
        case RSP_S_MAX_AGE:
            return rsp->sMaxAge != -1;
        case RSP_MUST_REVAL:
            return rsp->flags & FLAG_MUST_REVAL;
        case RSP_N_CACHE:
            return rsp->flags & FLAG_N_CACHE;
        case RSP_N_STORE:
            return rsp->flags & FLAG_N_STORE;
        case RSP_N_TRANSFORM:
            return rsp->flags & FLAG_N_TRANSFORM;
        case RSP_PUBLIC:
            return rsp->flags & FLAG_PUBLIC;
        case RSP_PRIVATE:
            return rsp->flags & FLAG_PRIVATE;
        case RSP_PROXY_REVAL:
            return rsp->flags & FLAG_PROXY_REVAL;
        default:
            return false;
    }
}

int responseHeaderValue(Response rsp, rspHeader hdr){
    switch (hdr) {
        case RSP_MAX_AGE:
            return rsp->maxAge;
        case RSP_S_MAX_AGE:
            return rsp->sMaxAge;
        case RSP_CONTENT_LEN:
            return rsp->contentLen;
        default:
            return -1;
    }
}

int responseGetAge(Response rsp){
    return rsp->cacheAge;
}
void responseSetAge(Response rsp, int age){
    rsp->cacheAge = age;
}

size_t responseToCharAry(Response rsp, char **msgp){
    char agestr[10];
    snprintf(agestr, 10, "%d", rsp->cacheAge);
    int agelen = strlen(agestr);
    int length = agelen + rsp->bodyLen + rsp->headLen + 9;
    *msgp = malloc(length);

    char *end = *msgp;
    memcpy(end, rsp->head, rsp->headLen - 2);
    end += rsp->headLen - 2;
    memcpy(end, "\r\nAge: ", 7);
    end += 7;
    memcpy(end, agestr, agelen);
    end += agelen;
    memcpy(end, "\r\n\r\n", 4);
    end += 4;
    memcpy(end, rsp->body, rsp->bodyLen);

    return length;
}
