#include "response_parser_dynamic.h"
#include "picohttpparser.h"
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
    int expLen;  /* -1 for chunked encoding */
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
    rsp->expLen = source->expLen;
    rsp->complete = source->complete;
    rsp->status = source->status;
    if(source->body == NULL){
        rsp->body = NULL;    
    }else{
        rsp->body = malloc(rsp->bodyLen + 1);
        memcpy(rsp->body, source->body, rsp->bodyLen + 1);
    }
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
    int reasonStart;
    if(sscanf(token, "%s %d %n", version, &(rsp->status), &reasonStart) == 2){
        rsp->reason = strdup(token + reasonStart);
        stripRearSpace(rsp->reason, -1);
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
        free(msg);
        return rsp;
    }

    Header h;
    int restLen = length - (rest - msg);
    if((h = getHeader(rsp->headers, "Content-Type")) != NULL && headerHasValue(h, "text/html", ";")){
        rsp->storeForward = true;
    }

    if((h = getHeader(rsp->headers, "Content-Length")) != NULL){
        rsp->expLen = atoi(h->value);
        rsp->body = calloc(1, rsp->expLen + 1);
    }else if(headerHasValue(getHeader(rsp->headers, "Transfer-Encoding"), "chunked" , ",")){
        rsp->expLen = -1;
        rsp->body = malloc(restLen + 1);
    }else{
        /* responses with no body */
        rsp->complete = true;
        free(msg);
        return rsp; 
    }

    if(rest != NULL){
        memcpy(rsp->body, rest, restLen + 1);
        rsp->bodyLen += restLen;
    }
    free(msg);

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

static void dechunk(char **inputp, int *lenp){
    char *original = *inputp; 
    char *tmp = malloc(*lenp);
    int chunkLen, offset;
    char *insertion = tmp;

    int n = sscanf(*inputp, "%x\r\n%n", &chunkLen, &offset);
    while(chunkLen != 0 || n != 1){
        *inputp += offset;
        memcpy(insertion, *inputp, chunkLen);
        insertion += chunkLen;
        *inputp += chunkLen; 
        n = sscanf(*inputp, "%x\r\n%n", &chunkLen, &offset);
    }

    *lenp = insertion - tmp;
    free(original);
    *inputp = tmp;
}


/* change transfer encoding to non-chunked */
static void finalizeChunkedResponse(Response rsp){
    if(!rsp->complete || rsp->expLen != -1){
        return;
    }
    struct phr_chunked_decoder decoder = {};
    size_t tmpLen = rsp->bodyLen;
    int err =  phr_decode_chunked(&decoder, rsp->body, &tmpLen);
    rsp->bodyLen = tmpLen;
    if(err < 0){
        fprintf(stderr, "Error at dechunking\n");
        return;
    }
    rsp->expLen = rsp->bodyLen;
    char lenStr[10];
    sprintf(lenStr, "%d", rsp->bodyLen);
    addHeader(&(rsp->headers), "Content-Length", lenStr);
    removeHeader(&(rsp->headers), "Transfer-Encoding");
}

/* Finalizes (replace transfer encoding if originally chunking) responses when complete is called */
bool responseComplete(Response rsp, int *remaining){
    if(rsp == NULL){
        return false;
    }
    if(rsp->partialHead){
        return false;
    }
    if(rsp->expLen != -1){
        int rem = rsp->expLen - rsp->bodyLen;
        if(remaining != NULL){
            *remaining = rem;
        }
        return (rem == 0);
    }else{
        /* Chunked case */
        if(rsp->bodyLen >= 5 && strncmp(rsp->body + rsp->bodyLen - 5, "0\r\n\r\n", 5) == 0){
            finalizeChunkedResponse(rsp);
            if(remaining != NULL){
                *remaining = 0;
            }
            return true;
        }
        if(remaining != NULL){
            *remaining = -1;
        }
        return false;
    }
}

/* Responses with partial header cannot be determined, so store unconditionally */
bool responseStoreForward(Response rsp){
    if(rsp->partialHead){
        return true;
    }
    return rsp->storeForward;
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

    if((*rspp)->body == NULL){
        (*rspp)->body = malloc(len);
    }else{
        int remainLen = 0;
        if((*rspp)->expLen != -1){
            remainLen = (*rspp)->expLen - (*rspp)->bodyLen;
        }

        if(remainLen < len){
            (*rspp)->body = realloc((*rspp)->body, (*rspp)->bodyLen + len + 1);
        }
    }

    memcpy((*rspp)->body + (*rspp)->bodyLen, msg, len + 1);
    (*rspp)->bodyLen += len;

    (*rspp)->complete = responseComplete(*rspp, NULL);
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

void responseUpdateBody(Response rsp, char *newBody, int newLen){
    free(rsp->body);
    rsp->bodyLen = newLen;
    rsp->body = malloc(newLen + 1);
    memcpy(rsp->body, newBody, newLen);
    rsp->body[newLen] = '\0';

    char lenStr[10];
    sprintf(lenStr, "%d", newLen);
    addHeader(&(rsp->headers), "Content-Length", lenStr);
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

    *strp = malloc(headLen + rsp->bodyLen + FIELD_BUFFER_SIZE); /* rough size, over allocating */

    int len;
    if(rsp->body == NULL){
        sprintf(*strp, "%s %d %s\r\n%s%n", "HTTP/1.1", rsp->status, rsp->reason, headStr, &len);
    }else{
        int startBody;
        sprintf(*strp, "%s %d %s\r\n%s\r\n%n", "HTTP/1.1", rsp->status, rsp->reason, headStr, &startBody);
        memcpy((*strp) + startBody, rsp->body, rsp->bodyLen);
        len = startBody + rsp->bodyLen;
    }
    free(headStr);
    return len;
}
