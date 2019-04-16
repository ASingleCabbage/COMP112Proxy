/*
    Multiple client proxy
    Cannot handle partial messages or SSL
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
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "request_parser.h"
#include "response_parser.h"
#include "ssl_utils.h"
#include "double_table.h"

#define LISTEN_BACKLOG 0
#define BUF_SIZE 1024
#define DEFAULT_PORT 80
#define TIMEOUT_SEC 30
#define DT_HINT 40

// todo maybe define a custom error enum for all the int returns
// todo consider making a network_util module to reduce clutter
// todo operations are currently done in sets of read/writes, so still blocking a bit

int initTcpSock(int port);
Response getResponse(Request req);
int connectServer(Request req);
int readMessage(int socket, char **msgp);
int handleStdin();

int handleSSLTransmit(int sourceSock, SSLState state);

int handleClient(int socket, SSLState *statep);

void errExit(char *msg){
    perror(msg);
    exit(EXIT_FAILURE);
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

int sendOkConnect(int clientSock){
    char *rspString = strdup("HTTP/1.1 200 Connection established\r\n\r\n");
    return write(clientSock, rspString, strlen(rspString));
}

int main(int argc, char **argv){
    if(argc != 2){
        errno = EINVAL;
        errExit("ERROR");
    }
    int port = (int)strtol(argv[1], NULL, 10);
    int mSock = initTcpSock(port);
    printf("Server running on address %d port %d\n", INADDR_ANY, port);

    fd_set active_fd_set, read_fd_set, ssl_fd_set;

    FD_ZERO(&active_fd_set);
    FD_ZERO(&ssl_fd_set);
    FD_SET(mSock, &active_fd_set);
    FD_SET(STDIN_FILENO, &active_fd_set);

    struct timeval timeSetting;
    timeSetting.tv_sec  = TIMEOUT_SEC;
    timeSetting.tv_usec = 0;
    struct timeval timeout = timeSetting;

    SSL_CTX *ctx = initCTX();
    loadCerts(ctx, "cert.pem", "key.pem");

    DTable dt = DTable_new(DT_HINT);

    while(true){
       fprintf(stderr, "READY\n");

        read_fd_set = active_fd_set;

        int n = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout);
        if(n < 0){
            errExit("ERROR on select");
        }else if(n == 0){
            timeout = timeSetting;
            /* Do something periodic like cleaning up the cache, closing connections, or sth */

        }else{
            for(int i = 0; i < FD_SETSIZE; i++){
                if(FD_ISSET(i, &read_fd_set)){
                    if(i == mSock){
                        int newSock = accept(mSock, NULL, NULL);
                        if(newSock < 0){
                            fprintf(stderr, "new connection accept failed, returned %d\n", newSock);
                            /* If accept raises errors we just keep calm and
                               carry on */
                            continue;
                        }
                        FD_SET(newSock, &active_fd_set);
                    }else if(i == STDIN_FILENO){
                        /* handles stdin for debugging and stuff */
                        handleStdin();
                    }else if(FD_ISSET(i, &ssl_fd_set)){
                        SSLState state = DTable_get(dt, i);
                        if(handleSSLTransmit(i, state) != 0){
                            int serverSock = SSL_get_fd(state->serverSSL);
                            int clientSock = SSL_get_fd(state->clientSSL);
                            SSL_shutdown(state->serverSSL);
                            SSL_shutdown(state->clientSSL);
                            close(serverSock);
                            close(clientSock);
                            FD_CLR(serverSock, &active_fd_set);
                            FD_CLR(clientSock, &active_fd_set);
                            FD_CLR(serverSock, &ssl_fd_set);
                            FD_CLR(clientSock, &ssl_fd_set);
                            DTable_remove(dt, clientSock, serverSock);
                        }
                    }
                    else{
                        SSLState state;
                        int stat;
                        if((stat = handleClient(i, &state)) < 0){
                            fprintf(stderr, "Closing connection %d\n", i);
                            close(i);
                            FD_CLR(i, &active_fd_set);
                        }else if(state != NULL){
                            int serverSock = SSL_get_fd(state->serverSSL);
                            FD_SET(serverSock, &active_fd_set);
                            FD_SET(i, &ssl_fd_set);
                            FD_SET(serverSock, &ssl_fd_set);
                            DTable_put(dt, i, serverSock, state);
                            sendOkConnect(i);
                        }
                    }
                }
            }
        }
    }
}

int handleStdin(){
    char buffer[11];
    int len = read(STDIN_FILENO, buffer, 10);
    buffer[len] = '\0';
    if(buffer[0] == 'q'){
        /* graceful termination option */
    }
    return 0;
}

int handleSSLTransmit(int sourceSock, SSLState state){
    if(state->state == CLIENT_CONNECT){
        SSL_accept(state->clientSSL);
        state->state = CLIENT_READ;
        return 0;
    }
    SSL *source;
    SSL *dest;
    if(SSL_get_fd(state->clientSSL) == sourceSock){
        source = state->clientSSL;
        dest = state->serverSSL;
    }else{
        source = state->serverSSL;
        dest = state->clientSSL;
    }
    char *msg;
    int bytes = readSSLMessage(source, &msg);
    if(bytes <= 0){
        return -1;
    }
    bytes = SSL_write(dest, msg, bytes);
    if(bytes <= 0){
        return -1;
    }
    return 0;
}

SSLState handleConnect(int clientSock, Request req, SSL_CTX *ctx){
    int serverSock = connectServer(req); //todo some form of error checking maybe
    return initSSLState(clientSock, serverSock, ctx);
}

// todo currently sever read/writes are still blocking connect...some additional
//      structure required to track connections
// returns -1 if error occurs, else 0
int handleClient(int clientSock, SSLState *statep, SSL_CTX *ctx){
    char *incoming;
    int n = readMessage(clientSock, &incoming);
    if(n == 0){
        return -1;
    }else if(n < 0){
        fprintf(stderr, "Error when reading from socket %d\n", socket);
        return -1;
    }

    fprintf(stderr, "Received\n%s\n", incoming);

    Request req = requestNew(incoming, n);
    if(req == NULL){
        fprintf(stderr, "Error when parsing request\n");
        //use errno to indicate error?
        return -1;
    }

    char *rspString; //not actually c string format, change name?
    int rspLen;
    if(requestMethod(req) == CONNECT){
        *statep = handleConnect(clientSock, req, ctx);
    }else{
        *statep = NULL;
        Response rsp = getResponse(req);
        rspLen = responseToCharAry(rsp, &rspString);
        fprintf(stderr, "Received\n%s\n", rspString);
        write(clientSock, rspString, rspLen); //todo error handling
        responseFree(rsp);
    }

    requestFree(req);
    free(incoming);
    return 0;
}

Response getResponse(Request req){
    int outSock = connectServer(req);
    char *msg;
    int len = requestToCharAry(req, &msg);

    if(write(outSock, msg, len) < 0){
        errExit("ERROR failed to write to outbound socket");
    }

    char *reply;
    int replen = readMessage(outSock, &reply);
    close(outSock);
    return responseNew(reply, replen);
}

//returns socket if successful, else -1
int connectServer(Request req){
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
        fprintf(stderr, "ERROR cannot find host with name [%s]\n", host);
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

    return outSock;
}

/* Notice: function does memory allocation on msg */
int readMessage(int socket, char ** msgp){
    char *buffer = calloc(BUF_SIZE, 1);
    int bufsize = BUF_SIZE;
    int msglen = 0;
    int n = read(socket, buffer, BUF_SIZE);
    if(n < 0){
        fprintf(stderr, "ERROR 1 failed to read from outgoing socket\n");
        return -1;
    }

    msglen += n;

    while(n == BUF_SIZE){
        char buffest[BUF_SIZE];
        bzero(buffest, BUF_SIZE);
        n = read(socket, buffest, BUF_SIZE);
        if(n < 0){
            fprintf(stderr, "ERROR 2 failed to read from outgoing socket\n");
            return -1;
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
