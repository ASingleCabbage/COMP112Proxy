#include "request_parser_dynamic.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#define FIELD_BUFFER_SIZE 2000

struct request{
    httpMethod method;
    int port;
    char *uri;
    char *host;
    Header headers;
    char *body;
};

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

Request requestNew(char * message, size_t length){
    if(length <= 0){
        return NULL;
    }

    char *msg = strdup(message);
    char *rest = msg;
    char *token;

    Request req = calloc(1, sizeof(struct request));
    token = strsep(&rest, " ");
    if(strcmp(token, "GET") == 0){
        req->method = GET;
    }else if(strcmp(token, "CONNECT") == 0){
        req->method = CONNECT;
    }else if(strcmp(token, "POST") == 0){
        req->method = POST;
    }else{
        req->method = OTHER;
        free(msg);

        msg = strdup(message);
        req->body = msg;
        req->port = length;
        return req;
    }

    req->port = -1;

    token = strsep(&rest, " ");
    req->uri = strdup(token);

    char uriNoPort[FIELD_BUFFER_SIZE];
    sscanf(token, "%[^:]:%d", uriNoPort, &(req->port));

    token = strsep(&rest, "\n");
    if(strncmp(token, "HTTP/1.1", 8) != 0){
        fprintf(stderr, "Warn: using unvalidated HTTP version %s\n", token);
    }

    token = strsep(&rest, "\n");

    while(token != NULL){
        if(strlen(token) == 0 || *token == '\r'){
            break;
        }
        char *fieldname = strsep(&token, ":");
        if(fieldname == NULL || token == NULL || *fieldname == '\0'){
            break;
        }

        char *fieldval = token + 1;

        if(strcmp(fieldname, "Host") == 0){
            char *host = strsep(&fieldval, ":");
            stripRearSpace(host, -1);
            req->host = strdup(host);
        }else{
            stripRearSpace(fieldname, -1);
            stripRearSpace(fieldval, -1);
            addHeader(&(req->headers), fieldname, fieldval);
        }
        token = strsep(&rest, "\n");
    }
    int bodyLen;
    if(rest != NULL && (bodyLen = strlen(rest) + 1) != 1)
    if(bodyLen != 0){
        req->body = strdup(rest);
    }

    free(msg);
    return req;
}

void requestFree(Request req){
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
    char *meth;
    switch (req->method) {
        case GET:
            meth = "GET";
            break;
        case CONNECT:
            meth = "CONNECT";
            break;
        case POST:
            meth = "POST";
            break;
        default:
            fprintf(stderr, "Error: attempting to print out an unsupported HTTP method\n");
            *strp = malloc(req->port + 1);
            memcpy(*strp, req->body, req->port + 1);
            return req->port;
    }

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
            sprintf(hostfield, "Host: %s", req->host);
        }else{
            sprintf(hostfield, "Host: %s:%d", req->host, req->port);
        }
    }

    int len;
    if(req->body == NULL){
        sprintf(*strp, "%s %s %s\r\n%s\r\n%s\r\n%n", meth, req->uri, "HTTP/1.1", hostfield, headStr, &len);
    }else{
        sprintf(*strp, "%s %s %s\r\n%s\r\n%s\r\n%s%n", meth, req->uri, "HTTP/1.1", hostfield, headStr, req->body, &len);
    }
    free(headStr);
    return len;
}
