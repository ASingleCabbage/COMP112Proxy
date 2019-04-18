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
#include <assert.h>
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
#include "write_buffer.h"

#define LISTEN_BACKLOG 6
#define BUF_SIZE 1500
#define DEFAULT_PORT 80
#define TIMEOUT_SEC 60
#define DT_HINT 60

// todo maybe define a custom error enum for all the int returns
// todo consider making a network_util module to reduce clutter
// todo operations are currently done in sets of read/writes, so still blocking a bit
/* implement some sort of write queue:
        once connection to server is established, add server socket to read_fd_set and write_fd_set
        add outgoing message into table (queue is blocking), along with destination info
        check if i ISSET of write_fd_set in select, and transmit its message
*/

// some function to differentiate between request or response header
int initTcpSock(int port);
// Response getResponse(Request req);
int connectServer(Request req);
int readMessage(int socket, char **msgp);
int handleStdin();

int handleSSLRead(int sourceSock, SSLState state, WriteBuffer wb, fd_set *write_fd_set);

int handleRead(int socket, GenericState *statep, SSL_CTX *ctx, WriteBuffer wb, DTable dt);

int handleWrite(int destSock, WriteEntry we, DTable dt);

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

void queueOkConnect(int destSock, WriteBuffer wb){
    char *rspString = strdup("HTTP/1.1 200 Connection established\r\n\r\n");
    WBuf_put(wb, HTTP_TYPE, destSock, rspString, strlen(rspString));
}

int main(int argc, char **argv){
    if(argc != 2){
        errno = EINVAL;
        errExit("ERROR");
    }
    int port = (int)strtol(argv[1], NULL, 10);
    int mSock = initTcpSock(port);
    printf("Server running on address %d port %d\n", INADDR_ANY, port);

    fd_set active_fd_set, read_fd_set, write_fd_set, ssl_fd_set;

    FD_ZERO(&active_fd_set);
    FD_ZERO(&write_fd_set);
    FD_ZERO(&ssl_fd_set);       //todo replace the functionality of ssl_fd_set with state types in dt
    FD_SET(mSock, &active_fd_set);
    FD_SET(STDIN_FILENO, &active_fd_set);

    struct timeval timeSetting;
    timeSetting.tv_sec  = TIMEOUT_SEC;
    timeSetting.tv_usec = 0;
    struct timeval timeout = timeSetting;

    // initGlobal();
    SSL_CTX *ctx = initCTX();
    // loadCerts(ctx, "server.crt", "server.key");

    DTable dt = DTable_new(DT_HINT);
    WriteBuffer wb = WBuf_new(DT_HINT);

    int remaining, n;
    WriteEntry we;

    while(true){
    //    fprintf(stderr, "READY\n");

        read_fd_set = active_fd_set;

        n = select(FD_SETSIZE, &read_fd_set, &write_fd_set, NULL, &timeout);
        if(n < 0){
            for (int i = 0; i < FD_SETSIZE; i++) {
                if(FD_ISSET(i, &read_fd_set))
                    printf("%d is in read_fd_set\n", i);
                if(FD_ISSET(i, &write_fd_set))
                printf("%d is in write_fd_set\n", i);
            }

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
                        fprintf(stderr, "New socket %d connected\n", newSock);
                        FD_SET(newSock, &active_fd_set);
                    }else if(i == STDIN_FILENO){
                        /* handles stdin for debugging and stuff */
                        handleStdin();
                    }else if(FD_ISSET(i, &ssl_fd_set)){
                        /* all active SSL connections go here */
                        SSLState state = DTable_get(dt, i);
                        int err;
                        if((err = handleSSLRead(i, state, wb, &write_fd_set)) != SSL_ERROR_NONE){
                            int serverSock = SSL_get_fd(state->serverSSL);
                            int clientSock = SSL_get_fd(state->clientSSL);
                            switch (err) {
                                case SSL_ERROR_ZERO_RETURN:
                                    //this shutdown step sometimes causes broken pipe error
                                    if(serverSock == i){
                                        SSL_shutdown(state->clientSSL);
                                    }else{
                                        SSL_shutdown(state->serverSSL);
                                    }
                                    fprintf(stderr, "ZERO_RETURN, normal shutdown\n");
                                    break;
                                case SSL_ERROR_SYSCALL:
                                case SSL_ERROR_SSL:
                                    fprintf(stderr, "SSL_ERROR, closing connection\n");
                                    break;
                                default:
                                    fprintf(stderr, "UNKNOWN ERROR when reading SSL: %d\n", err);
                            }
                            close(serverSock);
                            close(clientSock);
                            fprintf(stderr, "Clearing SSL %d %d from set\n", serverSock, clientSock);
                            FD_CLR(serverSock, &active_fd_set);
                            FD_CLR(clientSock, &active_fd_set);
                            FD_CLR(serverSock, &ssl_fd_set);
                            FD_CLR(clientSock, &ssl_fd_set);
                            FD_CLR(serverSock, &write_fd_set);
                            FD_CLR(clientSock, &write_fd_set);
                            SSLState ss = DTable_remove(dt, clientSock, serverSock);
                            free(ss);
                        }
                    }
                    else{
                        GenericState state;
                        int destSock;
                        if((destSock = handleRead(i, &state, ctx, wb, dt)) < 0){
                            fprintf(stderr, "Closing connection %d\n", i);
                            // todo close connection on the other size as well
                            GenericState state = DTable_get(dt, i);
                            if(state == NULL){
                                fprintf(stderr, "State doesn't exist in DTable...weird\n");
                                close(i);
                                FD_CLR(i, &active_fd_set);
                                FD_CLR(i, &read_fd_set);
                                FD_CLR(i, &write_fd_set);
                                WBuf_remove(wb, i);
                                continue;
                            }
                            int clientSock;
                            int serverSock;
                            if(state->type == SSL_TYPE){
                                SSLState ss = (SSLState) state;
                                clientSock = SSL_get_fd(ss->clientSSL);
                                serverSock = SSL_get_fd(ss->serverSSL);
                                SSL_shutdown(ss->serverSSL);
                                SSL_shutdown(ss->clientSSL);
                            }else{
                                PlainState ps = (PlainState) state;
                                clientSock = ps->clientSock;
                                serverSock = ps->serverSock;
                            }
                            fprintf(stderr, "Clearing non SSL %d %d from set\n", serverSock, clientSock);
                            free(DTable_remove(dt, serverSock, clientSock));
                            assert(DTable_get(dt, clientSock) == NULL);
                            assert(DTable_get(dt, serverSock) == NULL);
                            close(clientSock);
                            close(serverSock);
                            FD_CLR(clientSock, &active_fd_set);
                            FD_CLR(serverSock, &active_fd_set);
                            FD_CLR(clientSock, &read_fd_set);
                            FD_CLR(serverSock, &read_fd_set);
                            FD_CLR(clientSock, &write_fd_set);
                            FD_CLR(serverSock, &write_fd_set);
                            WBuf_remove(wb, clientSock);
                            WBuf_remove(wb, serverSock);
                        }else if(state != NULL && state->type == SSL_TYPE){
                            /* Non null states indicate a new connection */
                            /* CONNECT request: setting up records for SSL connection */
                            fprintf(stderr, "SSL server connected %d\n", destSock);
                            FD_SET(destSock, &active_fd_set);
                            FD_SET(i, &ssl_fd_set);
                            FD_SET(destSock, &ssl_fd_set);
                            DTable_put(dt, i, destSock, state);

                            FD_SET(destSock, &write_fd_set);
                            queueOkConnect(i, wb);
                        }else if(state != NULL && state->type == HTTP_TYPE){
                            /* plain HTTP, with write queued */
                            DTable_put(dt, i, destSock, state);
                            fprintf(stderr, "plain server connected %d\n", destSock);
                            FD_SET(destSock, &active_fd_set);
                            FD_SET(destSock, &write_fd_set);
                        }else{
                            /* existing connections */
                            FD_SET(destSock, &write_fd_set);
                        }
                    }
                }
                if((we = WBuf_get(wb, i, &remaining)) != NULL){
                    if(remaining == 0){
                        FD_CLR(i, &write_fd_set);
                    }
                    handleWrite(i, we, dt);
                }
            }
        }
    }
}

int handleWrite(int destSock, WriteEntry we, DTable dt){
    int stat;
    if(we->type == SSL_TYPE){
        SSLState state = DTable_get(dt, destSock);
        if(state == NULL){
            fprintf(stderr, "HANDLEWRITE: no DTable entry for %d\n", destSock);
            return -1;
        }
        SSL *destSSL;
        if(SSL_get_fd(state->serverSSL) == destSock){
            destSSL = state->serverSSL;
        }else{
            destSSL = state->clientSSL;
        }
        fprintf(stderr, "Writing to socket %d (ssl)\n", destSock);
        stat = SSL_write(destSSL, we->message, we->msgLen);
    }else{
        fprintf(stderr, "Writing to socket %d (plain)\n", destSock);
        stat = write(destSock, we->message, we->msgLen);
    }
    free(we->message);
    free(we);
    return stat;
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

/* returns a SSL error enum */
int handleSSLRead(int sourceSock, SSLState state, WriteBuffer wb, fd_set *wsp){
    if(state->state == CLIENT_CONNECT){
        generateCerts(&(state->clientSSL), state->serverSSL);
        SSL_accept(state->clientSSL);
        state->state = CLIENT_READ;
        return SSL_ERROR_NONE;
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
    // fprintf(stderr, "Received SSL\n%s\n", msg);
    if(bytes <= 0){
        return SSL_get_error(source, bytes);
    }

    WBuf_put(wb, SSL_TYPE, SSL_get_fd(dest), msg, bytes);
    FD_SET(SSL_get_fd(dest), wsp);
    return SSL_ERROR_NONE;
}

// todo currently sever read/writes are still blocking connect...some additional
//      structure required to track connections
// returns -1 if error occurs, else 0
// returns positive value if write is queued

//use states for all connection
int handleRead(int sourceSock, GenericState *statep, SSL_CTX *ctx, WriteBuffer wb, DTable dt){
    char *incoming = NULL;
    int n = readMessage(sourceSock, &incoming);
    if(n == 0){
        return -1;
    }else if(n < 0){
        fprintf(stderr, "Error when reading from socket %d\n", sourceSock);
        return -1;
    }

    // fprintf(stderr, "Received\n%s\n", incoming);

    *statep = NULL;
    GenericState state = DTable_get(dt, sourceSock);
    if(state == NULL){
        /* Fresh connection */
        // fprintf(stderr, "FRESH\n");
        Request req = requestNew(incoming, n);

        if(req == NULL){
            fprintf(stderr, "Error when parsing request\n");
            //use errno to indicate error?
            free(incoming);
            return -1;
        }

        int destSock = connectServer(req); //todo some form of error checking maybe
        if(requestMethod(req) == CONNECT){ //todo this assumption (only first message can be CONNECT may cause problems)
            *statep = (GenericState) initSSLState(sourceSock, destSock, ctx);
            free(incoming);
        }else{
            // fprintf(stderr, "WPUT by %d to %d\n", sourceSock, destSock);
            WBuf_put(wb, HTTP_TYPE, destSock, incoming, n);
            *statep = (GenericState) initPlainState(sourceSock, destSock);
        }
        requestFree(req);
        return destSock;
    }else if(state->type == HTTP_TYPE){
        // fprintf(stderr, "EXISTING HTTP\n");
        PlainState ps = (PlainState) state;
        int destSock;
        if(ps->clientSock == sourceSock){
            destSock = ps->serverSock;
        }else{
            destSock = ps->clientSock;
        }
        WBuf_put(wb, HTTP_TYPE, destSock, incoming, n);
        return destSock;
    }else{
        fprintf(stderr, "Uh oh this is not supposed to be printed (SSL)\n");
        free(incoming);
        //Existing SSL transmission: currently handled by another function
    }
    free(incoming);
    fprintf(stderr, "Uh oh this is not supposed to be printed\n");
    return -1;
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
        return -1;
    }

    /* building serveraddr */
    struct sockaddr_in serveraddr;
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
          server->h_length);

    int hostPort = requestPort(req);
    if(hostPort == -1){
        serveraddr.sin_port = htons(DEFAULT_PORT);
    }else{
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
        bufsize += BUF_SIZE;
        buffer = realloc(buffer, bufsize + 1);
        memcpy(buffer + msglen, buffest, n);
        msglen += n;
    }
    buffer[msglen] = '\0';
    *msgp = buffer;
    return msglen;
}
