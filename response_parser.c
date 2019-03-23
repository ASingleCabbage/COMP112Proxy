#include "response_parser.h"
#include <stdbool.h>
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
    int headLen;
    int bodyLen;
    int status;
    int maxAge;
    int sMaxAge;
    int cacheAge;
    char flags;
};

//todo cannot handle case where message header already contains age
Response responseNew(char * message, size_t length){
    char *msg = calloc(1, length);
    strcpy(msg, message);
    char *rest = msg;
    char *token;
    Response rsp = calloc(1, sizeof(struct response));

    rsp->maxAge = -1;
    rsp->sMaxAge = -1;

    token = strsep(&rest, " "); /* HTTP Version */
    token = strsep(&rest, " ");
    rsp->status = strtol(token, NULL, 10);
    token = strsep(&rest, "\n"); /* Reason Phrase */

    token = strsep(&rest, "\n");
    char buf1[FIELD_BUFFER_SIZE];
    while((token != NULL) | (strlen(token) == 0)){
        if(sscanf(token, "Cache-Control: %[^\n]", buf1)){
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
                }else if(strncmp(tk, "s-maxage=", 9) == 0){
                    rsp->sMaxAge = strtol(tk + 9, NULL, 10);
                }
                tk = strsep(&br, " ");
            }
        }
    }
    rsp->headLen = token - msg;
    rsp->head = calloc(1, rsp->headLen);
    strncpy(rsp->head, message, rsp->headLen);

    rsp->bodyLen = length - rsp->headLen - 2;
    rsp->body = calloc(1, rsp->bodyLen);
    strncpy(rsp->body, message + rsp->headLen + 2, rsp->bodyLen);

    free msg;
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
    }
}

int responseHeaderValue(Response rsp, rspHeader hdr){
    switch (hdr) {
        case RSP_MAX_AGE:
            return rsp->maxAge;
        case RSP_S_MAX_AGE:
            return rsp->sMaxAge;
        default:
            return -1;
    }
}

int responseGetAge(Response rsp, int age){
    return rsp->cacheAge;
}
void responseSetAge(Response rsp, int age){
    rsp->cacheAge = age;
}

size_t responseToString(Response rsp, char **sp){
    char agestr[10];
    itoa(rsp->cacheAge, agestr, 10);
    int agelen = strlen(agestr);
    int length = agelen + rsp->bodyLen + rsp->headLen + 9;
    *sp = malloc(length);

    char *end = *sp;
    memcpy(end, resp->head, resp->headLen);
    end += resp->headLen;
    memcpy(end, "\r\nAge: ", 7);
    end += 7;
    memcpy(end, agestr, agelen);
    end += agelen;
    memcpy(end, "\r\n\r\n", 2);
    end += 2;
    memcpy(end, resp->body, resp->bodyLen);

    return length;
}
