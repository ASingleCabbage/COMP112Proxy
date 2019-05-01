#include "response_parser_dynamic.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#define FIELD_BUFFER_SIZE 2000

/* Partial header is set to true if the first call to responseNew isnt passed in a
   response with complete headers */
struct response{
    char *reason;
    Header headers;
    char *body;
    bool storeForward;
    bool partialHead;
    int bodyLen;
    int chunkRemain;
    bool complete;
    int status;
};

Response responseDuplicate(Response source){
    Response rsp = malloc(sizeof(struct response));
    rsp->reason = strdup(source->reason);
    rsp->headers = dupHeadList(source->headers);
    rsp->storeForward = source->storeForward;
    rsp->partialHead = source->partialHead;
    rsp->bodyLen = source->bodyLen;
    rsp->chunkRemain = source->chunkRemain;
    rsp->complete = source->complete;
    rsp->status = source->status;
    rsp->body = malloc(rsp->bodyLen + 1);
    memcpy(rsp->body, source->body, rsp->bodyLen + 1);
    return rsp;
}

static void stripRearSpace(char *str, int len){
    int index;
    if(len < 0){
        index = strlen(str) - 1;
    }else{
        index = len - 1;
    }
    while(index >= 0){
        if(isspace(str[index])){
            str[index] = '\0';
        }else{
            return;
        }
        index--;
    }
}
static bool partialHeader(char *msg, size_t length){
    char *front = malloc(length + 1);
    memcpy(front, msg, length);
    front[length] = '\0'; //making it a c string so strsep wont overflow
    char *rest = front;
    char *token;

    token = strsep(&rest, "\n");
    while (rest != NULL) {
        if(*token == '\r'){
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
        rsp->partialHead = true;
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
        token += 1; /* move past the : (I think anyway) */
        stripRearSpace(tk1, -1);
        stripRearSpace(token, -1);
        addHeader(&(rsp->headers), tk1, token);

        token = strsep(&rest, "\n");
    }

    if(rest == NULL){
        rsp->chunkRemain = -1;
        free(msg);
        return rsp;
    }

    Header h;
    if((h = getHeader(rsp->headers, "Content-Type")) != NULL && headerHasValue(h, "text/html", ";")){
        rsp->storeForward = true;
    }

    if((h = getHeader(rsp->headers, "Content-Length")) != NULL){
        rsp->chunkRemain = -1;
        rsp->body = calloc(1, atoi(h->value) + 1);

        int restLen = length - (rest - msg);
        if(rest != NULL){
            memcpy(rsp->body, rest, restLen + 1);
            rsp->bodyLen += restLen;
        }
        free(msg);
    }else if((h = getHeader(rsp->headers, "Transfer-Encoding")) != NULL){
        /* May or may not have to check for chunked mode */
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

            // strncpy(pos, rest, restLen + 1); //todo this overflows on some links on wikipedia
            memcpy(pos, rest, restLen + 1); //todo this overflows on some links on wikipedia (links ending with ':'?)
            rsp->bodyLen += restLen;
            rsp->chunkRemain = chunkLen - restLen;
        }
        free(msg);
    }else{
        /* responses with no body */
        rsp->bodyLen = 0;
        rsp->chunkRemain = -1;
        rsp->body = strdup("");

    }
    return rsp;
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

/* change transfer encoding to non-chunked */
static void finalizeResponse(Response rsp){
    char *msgStr;
    responseToString(rsp, &msgStr);

    if(rsp->chunkRemain != -1){
        // fprintf(stderr, "CHUNK %d, body len %d\n", rsp->chunkRemain, rsp->bodyLen);

        char lenStr[10];
        sprintf(lenStr, "%d", rsp->bodyLen);
        addHeader(&(rsp->headers), "Content-Length", lenStr);
    }
    rsp->chunkRemain = -1;
}

/* Finalizes (replace transfer encoding if originally chunking) responses when complete is called */
bool responseComplete(Response rsp, int *remaining){
    if(rsp == NULL){
        return false;
    }
    if(rsp->partialHead){
        return false;
    }
    Header h;
    char *headers;
    toStringHeader(rsp->headers, &headers);
    if((h = getHeader(rsp->headers, "Content-Length")) != NULL){
        int clen = atoi(h->value);
        int rem = clen - rsp->bodyLen;
        if(remaining != NULL){
            *remaining = rem;
        }
        return (rem == 0);
    }else if(rsp->chunkRemain == 0){
        finalizeResponse(rsp);
        return true;
    }
    return (rsp->chunkRemain == -1); /* returns true if not chunked */
}

/* Responses with partial header cannot be determined, so store unconditionally */
bool responseStoreForward(Response rsp){
    fprintf(stderr, "Store Forward check\n");
    if(rsp->partialHead){
        fprintf(stderr, "returned true\n");
        return true;
    }
    fprintf(stderr, "returned %d\n", rsp->storeForward);
    return rsp->storeForward;
    // return false;
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
        tmp->storeForward = true;
        *rspp = tmp;
        return true;
    }
    return false;
}

bool responseAppendBody(Response *rspp, char *msg, int len){
    if((*rspp)->partialHead){
        appendPartial(rspp, msg, len);
        return (*rspp)->complete;
    }

    if(msg == NULL || len == 0){
        assert(false);      /* debug use, remove when deploying*/
        return (*rspp)->complete;
    }
    if((*rspp)->chunkRemain >= 0){
        if((*rspp)->chunkRemain == 0){
            int chunkLen = 0;
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
                }while(chunkLen < len);

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
        char *rspStr;
        responseToString(*rspp, &rspStr);

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

int responseBody(Response rsp, char **bodyp){
    *bodyp = rsp->body;
    return rsp->bodyLen;
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
