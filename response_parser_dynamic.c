#include "response_parser_dynamic.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define FIELD_BUFFER_SIZE 512

struct response{
    char *reason;
    Header headers;
    char *body;
    int status;
};

Response responseNew(char * message, size_t length){
    if(length <= 0){
        return NULL;
    }

    char *msg = malloc(length + 1);
    memcpy(msg, message, length);
    msg[length] = '\0'; //making it a c string so strsep wont overflow
    char *rest = msg;
    char *token;
    Response rsp = calloc(1, sizeof(struct response));

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

    char buf1[FIELD_BUFFER_SIZE];
    char buf2[FIELD_BUFFER_SIZE];
    int num1;
    while(token != NULL){
        if(strlen(token) == 0){
            break;
        }
        int numParsed = sscanf(token, "%[^:]%n:%s", buf1, &num1, buf2);
        buf1[num1] = '\0';
        if(numParsed < 2){
            break;
        }

        char *fieldname = malloc(num1 + 1);
        memcpy(fieldname, buf1, num1);
        fieldname[num1] = '\0';

        char *fieldval = malloc(strlen(buf2) + 1);
        strcpy(fieldval, buf2);
        addHeader(&(rsp->headers), fieldname, fieldval);

        token = strsep(&rest, "\n");
    }
    int bodyLen;
    if(rest != NULL && (bodyLen = strlen(rest) + 1) != 1)
    if(bodyLen != 0){
        rsp->body = malloc(bodyLen);
        memcpy(rsp->body, rest, bodyLen);
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
