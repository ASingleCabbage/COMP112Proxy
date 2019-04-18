/*
    Simple proxy. Single client no caching
    Cannot handle partial messages
    This might be broken as I tried to make it work with SSL before realizing that
    SSL needs select to work
*/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "request_parser.h"
#include "response_parser.h"
#include "cache.h"

#define LISTEN_BACKLOG 0
#define BUF_SIZE 1024
#define DEFAULT_PORT 80
#define DEFAULT_SECURE_PORT 80

int initTcpSock(int port);
Response getResponse(Request req, Cache csh);
int getSecureResponse(Request req, char **rspp);


int readUntilDone(int socket, char **msgp);

void errExit(char *msg){
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv){
    if(argc != 2){
        errno = EINVAL;
        errExit("ERROR");
    }

    int port = (int)strtol(argv[1], NULL, 10);
    int mSock = initTcpSock(port);

    Cache csh = cache_new();

    printf("Server running on address %d port %d\n", INADDR_ANY, port);

    while (1){
        int cSock = accept(mSock, NULL, NULL);
        fprintf(stderr, "\n[READY]\n");
        /* Notice: incoming is dynamically allocated in readUntilDone() */
        char *incoming;
        int n = readUntilDone(cSock, &incoming);

        fprintf(stderr, "Received request (%d): \n%s\n", n, incoming);

        Request req = requestNew(incoming, n);
        if(req == NULL){
            continue;
        }

        char *rspString;
        int rspLen;
        if(requestMethod(req) == CONNECT){
            rspLen = getSecureResponse(req, &rspString);
        }else{
            Response rsp = getResponse(req, csh);
            rspLen = responseToCharAry(rsp, &rspString);
        }

        fprintf(stderr, "Received response (%d): \n%s\n", rspLen, rspString);

        n = write(cSock, rspString, rspLen);
        if(n < 0){
            errExit("ERROR writing to client socket");
        }
        // printf("written %d bytes out of %d bytes\n\n", n, rspLen);
        // FILE *log = fopen(respLog, "a");
        // fwrite(reply, 1, replyLen, log);
        // fprintf(log, "[END OF RESPONSE]\n");
        // fclose(log);

        // close(cSock);
        free(incoming);
    }
}

int initTcpSock(int port){
    /* socket with IPv4, TCP, IP protocol 0  */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        errExit("ERROR socket creation failed");
    }

    int optionVal = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optionVal, sizeof(int));

    struct sockaddr_in serveraddr;
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = port;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short) port);

    if(bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
        errExit("ERROR socket binding failed");
    }

    if(listen(sock, LISTEN_BACKLOG) < 0){
        errExit("ERROR listening to socket failed");
    }

    return sock;
}

Response getResponse(Request req, Cache csh){

    // Attempt to get response from cache
    Response rsp;
    rsp = get_from_cache(csh, req);
    if (rsp != NULL)
        return rsp;
    // Otherwise, continue to get from server

    /* creating outbout socket */
    int outSock = socket(AF_INET, SOCK_STREAM, 0);
    if(outSock < 0){
        errExit("ERROR failed to create outbound socket");
    }

    /* getting host via DNS */
    char *host;
    requestHost(req, &host);
    struct hostent *server = gethostbyname(host);
    if(server == NULL){
        fprintf(stderr, "ERROR cannot find host with name %s\n", host);
        exit(EXIT_FAILURE);
    }

    /* building serveraddr */
    struct sockaddr_in serveraddr;
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
          server->h_length);

    int hostPort = requestPort(req);
    if(hostPort == -1){
        printf("Using default port\n");
        serveraddr.sin_port = htons(DEFAULT_PORT);
    }else{
        printf("Using custom port %d\n", hostPort);
        serveraddr.sin_port = htons(hostPort);
    }

    /* connect with server */
    if(connect(outSock, (const struct sockaddr *)&serveraddr,
               sizeof(serveraddr)) < 0){
        errExit("ERROR connecting");
    }

    char *msg;
    int len = requestToCharAry(req, &msg);
    // fprintf(stderr, "CHAR ARY with length %d and msg %s\n", len, msg);

    int n = write(outSock, msg, len);
    if(n < 0){
        errExit("ERROR failed to write to outbound socket");
    }

    char *reply;
    int replen = readUntilDone(outSock, &reply);
    // fprintf(stderr, "Reply received\n");
    close(outSock);

    rsp = responseNew(reply, replen);
    cache_add(csh, req, rsp);
    return rsp;
}

int getSecureResponse(Request req, char **rspp){
    /* creating outbout socket */
    int outSock = socket(AF_INET, SOCK_STREAM, 0);
    if(outSock < 0){
        errExit("ERROR failed to create outbound socket");
    }

    /* getting host via DNS */
    char *host;
    requestHost(req, &host);
    struct hostent *server = gethostbyname(host);
    if(server == NULL){
        fprintf(stderr, "ERROR cannot find host with name %s\n", host);
        exit(EXIT_FAILURE);
    }

    /* building serveraddr */
    struct sockaddr_in serveraddr;
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
          server->h_length);

    int hostPort = requestPort(req);
    if(hostPort == -1){
        printf("Using default port\n");
        serveraddr.sin_port = htons(DEFAULT_PORT);
    }else{
        printf("Using custom port %d\n", hostPort);
        serveraddr.sin_port = htons(hostPort);
    }

    /* connect with server */
    if(connect(outSock, (const struct sockaddr *)&serveraddr,
               sizeof(serveraddr)) < 0){
        errExit("ERROR connecting");
    }

    char *msg;
    int len = requestToCharAry(req, &msg);

    int n = write(outSock, msg, len);
    if(n < 0){
        errExit("ERROR failed to write to outbound socket");
    }

    return readUntilDone(outSock, rspp);
}

/* Notice: function does memory allocation on msg */
int readUntilDone(int socket, char ** msgp){
    char *buffer = calloc(BUF_SIZE, 1);
    int bufsize = BUF_SIZE;
    int msglen = 0;
    int n = read(socket, buffer, BUF_SIZE);
    if(n < 0){
        errExit("ERROR failed to read from outgoing socket");
    }

    fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);

    msglen += n;

    while(n == BUF_SIZE){
        char buffest[BUF_SIZE];
        bzero(buffest, BUF_SIZE);
        n = read(socket, buffest, BUF_SIZE);
        fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);
        if(n < 0){
            errExit("ERROR failed to read from outgoing socket");
        }else if(n == 0){
            break;
        }
        msglen += n;
        bufsize += BUF_SIZE;
        buffer = realloc(buffer, bufsize + 1);
        strncat(buffer, buffest, n);
    }
    *msgp = buffer;
    return msglen;
}
