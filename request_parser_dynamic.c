#include "request_parser_dynamic.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define FIELD_BUFFER_SIZE 512

struct request{
    httpMethod method;
    int port;
    char *uri;
    char *host;
    Header headers;
    char *body;
};

Request requestNew(char * message, size_t length){
    if(length <= 0){
        return NULL;
    }

    char *msg = malloc(length + 1);
    memcpy(msg, message, length);
    msg[length] = '\0'; //making it a c string so strsep wont overflow
    char *rest = msg;
    char *token;

    Request req = calloc(1, sizeof(struct request));

    //initialize request with proper values
    req->port = -1;

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
    req->uri = malloc(strlen(token) + 1);
    strcpy(req->uri, token);

    char uriNoPort[FIELD_BUFFER_SIZE];
    sscanf(token, "%[^:]:%d", uriNoPort, &(req->port));

    token = strsep(&rest, "\n");
    if(strncmp(token, "HTTP/1.1", 8) != 0){
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
        strcpy(buf2, token + num1 + 1);
        if(numParsed < 2){
            break;
        }
        if(strcmp(buf1, "Host") == 0){
            char fieldval[FIELD_BUFFER_SIZE];
            int vallen;
            sscanf(buf2, "%[^:]%n:%d", fieldval, &vallen, &(req->port));

            /* stripping whitespace because excluding it in [^:] doesn't work */
            sscanf(fieldval, "%s%n", fieldval, &vallen);
            
            req->host = malloc(vallen + 1);
            memcpy(req->host, fieldval, vallen);
            (req->host)[vallen] = '\0';
        }else{
            char *fieldname = malloc(num1 + 1);
            memcpy(fieldname, buf1, num1);
            fieldname[num1] = '\0';

            char *fieldval = malloc(strlen(buf2) + 1);
            strcpy(fieldval, buf2);
            addHeader(&(req->headers), fieldname, fieldval);
        }
        token = strsep(&rest, "\n");
    }
    int bodyLen;
    if(rest != NULL && (bodyLen = strlen(rest) + 1) != 1)
    if(bodyLen != 0){
        req->body = malloc(bodyLen);
        memcpy(req->body, rest, bodyLen);
    }


    free(msg);
    return req;
}

void requestFree(Request req){
    fprintf(stderr, "FREEING\n");
    if(req == NULL){
        return;
    }
    freeHeader(req->headers);
    free(req->body);
    free(req->uri);
    free(req->host);
    free(req);
}

httpMethod requestMethod(Request req){
    return req->method;
}

char *requestHost(Request req){
    return req->host;
}

int requestPort(Request req){
    return req->port;
}

char *requestUri(Request req){
    return req->uri;
}

Header requestHeader(Request req, char *fieldname){
    return getHeader(req->headers, fieldname);
}

void requestAddHeader(Request req, char *fieldname, char *fieldval){
    addHeader(&(req->headers), fieldname, fieldval);
}

int requestToString(Request req, char **strp){
    char *headStr;
    int headLen;
    if(req->headers == NULL){
        headLen = 0;
        headStr = malloc(1); /* allocating something so we can free without checking */
        headStr[0] = '\0';
    }else{
        headLen = toStringHeader(req->headers, &headStr);
    }

    int bodyLen = 0;
    if(req->body != NULL){
        bodyLen = strlen(req->body);
    }

    *strp = malloc(headLen + bodyLen + FIELD_BUFFER_SIZE); /* rough size, over allocating */

    char hostfield[FIELD_BUFFER_SIZE];
    hostfield[0] ='\0';

    if(req->host != NULL){
        if(req->port < 0){
            sprintf(hostfield, "Host: %s\r\n", req->host);
        }else{
            sprintf(hostfield, "Host: %s:%d\r\n", req->host, req->port);
        }
    }

    char *meth;
    switch (req->method) {
        case GET:
            meth = "GET";
            break;
        case CONNECT:
            meth = "CONNECT";
            break;
        default:
            fprintf(stderr, "Error: attempting to print out an unsupported HTTP method\n");
            return -1;
    }

    int len;
    if(req->body == NULL){
        sprintf(*strp, "%s %s %s\r\n%s%s%n", meth, req->uri, "HTTP/1.1", hostfield, headStr, &len);
    }else{
        sprintf(*strp, "%s %s %s\r\n%s%s\r\n%s%n", meth, req->uri, "HTTP/1.1", hostfield, headStr, req->body, &len);
    }
    free(headStr);
    return len;
}
