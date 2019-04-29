#include "request_parser_dynamic.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define FIELD_BUFFER_SIZE 2000

struct request{
    httpMethod method;
    int port;
    char *uri;
    char *host;
    Header headers;
    char *body;
};

Request requestNew(char * message, size_t length){
    // fprintf(stderr, "MESSAGE:\n%s\n", message);
    if(length <= 0){
        return NULL;
    }

    char *msg = malloc(length + 1);
    memcpy(msg, message, length);
    msg[length] = '\0'; //making it a c string so strsep wont overfloA
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

        msg = malloc(length + 1);
        memcpy(msg, message, length);
        msg[length] = '\0';
        req->body = msg;
        req->port = length;
        return req;
    }

    req->port = -1;

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

    char *fieldname;
    while(token != NULL){
        // fprintf(stderr, "TOKEN (%d): %d\n",strlen(token), *token);
        if(strlen(token) == 0 || *token == '\r'){
            break;
        }
        char *tk1 = strsep(&token, ":");
        if(tk1 == NULL || token == NULL || *tk1 == '\0'){
            break;
        }
        fieldname = malloc(strlen(tk1) + 1);
        strcpy(fieldname, tk1);

        token += 1;
        int tokLen = strlen(token);
        char *fieldval = malloc(tokLen + 1);
        memcpy(fieldval, token, tokLen);
        fieldval[tokLen - 1] = '\0';

        if(strcmp(fieldname, "Host") == 0){
            char *host = strsep(&fieldval, ":");
            int hostLen = strlen(host);
            req->host = malloc(hostLen + 1);
            memcpy(req->host, host, hostLen + 1);
            // (req->host)[strlen(host)] = '\0';
        }else{
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
    // fprintf(stderr, "FREEING\n");
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
            sprintf(hostfield, "Host: %s\r\n", req->host);
        }else{
            sprintf(hostfield, "Host: %s:%d\r\n", req->host, req->port);
        }
    }


    int len;
    if(req->body == NULL){
        sprintf(*strp, "%s %s %s\r\n%s%s\r\n%n", meth, req->uri, "HTTP/1.1", hostfield, headStr, &len);
    }else{
        sprintf(*strp, "%s %s %s\r\n%s%s\r\n%s%n", meth, req->uri, "HTTP/1.1", hostfield, headStr, req->body, &len);
    }
    free(headStr);
    return len;
}
