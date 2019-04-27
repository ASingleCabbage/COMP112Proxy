#include "response_parser_dynamic.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define FIELD_BUFFER_SIZE 2000

/* Partial header is set to true if the first call to responseNew isnt passed in a
   response with complete headers */
struct response{
    char *reason;
    Header headers;
    char *body;
    bool partialHeader;
    int bodyLen;
    int chunkRemain;
    bool complete;
    int status;
};

static bool partialHeader(char *msg, size_t length){
    char *front = malloc(length + 1);
    memcpy(front, msg, length);
    front[length] = '\0'; //making it a c string so strsep wont overflow
    char *rest = front;
    char *token;

    token = strsep(&rest, "\n");
    while (rest != NULL) {
        if(*token == '\0'){
            /* empty token means that break between header and body is encountered */
            free(front);
            return false;
        }
        token = strsep(&rest, "\n");
    }
    return true;
}


Response responseNew(char * message, size_t length){
    if(length <= 0){
        return NULL;
    }

    char *msg = malloc(length + 1);
    memcpy(msg, message, length);
    msg[length] = '\0'; //making it a c string so strsep wont overflow
    Response rsp = calloc(1, sizeof(struct response));
    if(partialHeader(message, length)){
        rsp->partialHeader = true;
        rsp->body = msg;
        rsp->bodyLen = length;
        return rsp;
    }
    char *rest = msg;
    char *token;

    token = strsep(&rest, "\n");
    char version[FIELD_BUFFER_SIZE];
    char reason[FIELD_BUFFER_SIZE];
    if(sscanf(token, "%s %d %s", version, &(rsp->status), reason) == 3){
        int len = strlen(reason) + 1;
        rsp->reason = malloc(len);
        memcpy(rsp->reason, reason, len);
    }
    if(strncmp(version, "HTTP/1.1", 8) != 0){
        fprintf(stderr, "Warn: using unvalidated HTTP version %s\n", token);
    }

    token = strsep(&rest, "\n");
    char *tk1;
    while(token != NULL){
        if(strlen(token) == 0 || *token == '\r'){
            break;
        }
        tk1 = strsep(&token, ":");
        if(tk1 == NULL || token == NULL){
            fprintf(stderr, "Error when parsing headers, continuing...\n");
            break;
        }
        char *fieldname = malloc(strlen(tk1) + 1);
        strcpy(fieldname, tk1);

        token += 1;
        int tokLen = strlen(token);
        char *fieldval = malloc(tokLen + 1);
        memcpy(fieldval, token, tokLen + 1);
        addHeader(&(rsp->headers), fieldname, fieldval);

        token = strsep(&rest, "\n");
    }

    if(rest == NULL){
        rsp->chunkRemain = -1;
        free(msg);
        return rsp;
    }

    Header h;
    if((h = getHeader(rsp->headers, "Content-Length")) != NULL){
        rsp->chunkRemain = -1;
        rsp->body = calloc(1, atoi(h->value) + 1);

        int restLen = length - (rest - msg);
        if(rest != NULL){
            memcpy(rsp->body, rest, restLen + 1);
            rsp->bodyLen += restLen;
        }
        free(msg);
        return rsp;
    }else{
        /* if no content length is specified, assume uses chunked mode */
        /* the strcmp may break if some other transfer encoding is combined with chunked */
        token = strsep(&rest, "\n");
        int chunkLen = strtol(token, NULL, 16);
        int restLen = 0;
        if(rest != NULL){
            restLen = strlen(rest);
        }

        if(chunkLen == 0){
            rsp->complete = true;
            free(msg);
            return rsp;
        }else if(chunkLen >= restLen){
            /* Contains one partial chunk */
            rsp->body = malloc(chunkLen + 1);
            rsp->bodyLen = restLen;
            memcpy(rsp->body, rest, restLen + 1);
            rsp->chunkRemain = chunkLen - restLen;
        }else{
            rsp->body = malloc(restLen + 1);
            char *pos = rsp->body;
            do {
                memcpy(pos, rest, chunkLen);
                rest += chunkLen;
                restLen -= chunkLen;
                rsp->bodyLen += chunkLen;
                pos += chunkLen;
                token = strsep(&rest, "\n");
                if(token == NULL){
                    assert(false);
                    chunkLen = 0;
                    restLen = 0;
                }else{
                    chunkLen = strtol(token, NULL, 16);
                }
            } while(chunkLen < restLen && chunkLen != 0);

            memcpy(pos, rest, restLen + 1);
            rsp->bodyLen += restLen;
            rsp->chunkRemain = chunkLen - restLen;
        }
        free(msg);
        return rsp;
    }
}

void responseFree(Response rsp){
    if(rsp == NULL){
        return;
    }
    freeHeader(rsp->headers);
    free(rsp->reason);
    free(rsp->body);
    free(rsp);
}

bool responseComplete(Response rsp, int *remaining){
    Header h;
    if((h = getHeader(rsp->headers, "Content-Length")) != NULL){
        int clen = atoi(h->value);
        if(remaining != NULL){
            *remaining = clen - rsp->bodyLen;
        }
        return (rsp->bodyLen >= clen);
    }else if(rsp->chunkRemain == 0){
        return true;
    }
    return (rsp->chunkRemain == -1); /* returns true if not chunked */
}

/* Returns true if header component complete */
static bool appendPartial(Response *rspp, char *msg, int len){
    Response rsp = *rspp;
    rsp->body = realloc(rsp->body, rsp->bodyLen + len + 1);
    memcpy(rsp->body + rsp->bodyLen, msg, len);
    rsp->bodyLen += len;
    (rsp->body)[rsp->bodyLen] = '\0';

    if(!partialHeader(msg, len)){
        Response tmp = responseNew(rsp->body, rsp->bodyLen);
        responseFree(rsp);
        *rspp = tmp;
        return true;
    }
    return false;
}


bool responseAppendBody(Response *rspp, char *msg, int len){
    if((*rspp)->partialHeader){
        appendPartial(rspp, msg, len);
        return (*rspp)->complete;
    }

    if(msg == NULL || len == 0){
        assert(false);      /* debug use, remove when deploying*/
        return (*rspp)->complete;
    }
    if((*rspp)->chunkRemain >= 0){
        if((*rspp)->chunkRemain == 0){
            unsigned chunkLen = 0;
            (*rspp)->body = realloc((*rspp)->body, len + (*rspp)->bodyLen);

            int hexLen;
            sscanf(msg, "%x\r\n%n", &chunkLen, &hexLen);
            if(chunkLen == 0){
                (*rspp)->complete = true;
                return (*rspp)->complete;
            }

            msg += hexLen;
            len -= hexLen;

            char *insertPos = (*rspp)->body + (*rspp)->bodyLen;
            if(chunkLen > len){
                /* partial chunk only */
                memcpy(insertPos, msg, len + 1);
                (*rspp)->bodyLen += len;
                (*rspp)->chunkRemain = chunkLen - len;
            }else{
                /* full or more than one chunk */
                do {
                    memcpy(insertPos, msg, chunkLen);
                    (*rspp)->bodyLen += chunkLen;
                    insertPos = insertPos + chunkLen;
                    sscanf(msg, "%x\r\n%n", &chunkLen, &hexLen);
                    msg += hexLen;
                    len -= hexLen;
                }while(chunkLen < len); /* Warn: Mixed sign comparison */

                if(chunkLen == 0){
                    (*rspp)->complete = true;
                }else{
                    memcpy(insertPos, msg, len + 1);
                    (*rspp)->bodyLen += len;
                    (*rspp)->chunkRemain = chunkLen - len;
                }
            }
            return (*rspp)->complete;
        }
    }else{
        int rem;
        responseComplete((*rspp), &rem);
        if(rem == len){
            (*rspp)->complete = true;
        }else if(rem < len){
            fprintf(stderr, "Appending message %d larger than expected size... %d, yolo?\n", (len - rem), rem);
            (*rspp)->complete = true;
        }
        if((*rspp)->bodyLen == 0){
            (*rspp)->body = calloc(1, rem + 1);
        }

        memcpy((*rspp)->body + (*rspp)->bodyLen, msg, len + 1);
        (*rspp)->bodyLen += len;
    }
    return (*rspp)->complete;
}

int responseStatus(Response rsp, char **reasonp){
    if(*reasonp != NULL){
        *reasonp = rsp->reason;
    }
    return rsp->status;
}

Header responseHeader(Response rsp, char *fieldname){
    return getHeader(rsp->headers, fieldname);
}

void responseAddHeader(Response rsp, char *fieldname, char *fieldval){
    addHeader(&(rsp->headers), fieldname, fieldval);
}

int responseToString(Response rsp, char **strp){
    char *headStr;
    int headLen;
    if(rsp->headers == NULL){
        headLen = 0;
        headStr = malloc(1); /* allocating something so we can free without checking */
        headStr[0] = '\0';
    }else{
        headLen = toStringHeader(rsp->headers, &headStr);
    }

    int bodyLen = 0;
    if(rsp->body != NULL){
        bodyLen = strlen(rsp->body);
    }

    *strp = malloc(headLen + bodyLen + FIELD_BUFFER_SIZE); /* rough size, over allocating */

    int len;
    if(rsp->body == NULL){
        sprintf(*strp, "%s %d %s\r\n%s%n", "HTTP/1.1", rsp->status, rsp->reason, headStr, &len);
    }else{
        sprintf(*strp, "%s %d %s\r\n%s\r\n%s%n", "HTTP/1.1", rsp->status, rsp->reason, headStr, rsp->body, &len);
    }
    free(headStr);
    return len;
}
