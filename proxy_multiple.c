/*
    Multiple client proxy, SSL Inspection and Cache
    COMP 112 Final Project - Hao-Wei (Daniel) Lan
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
#include <fcntl.h>

#include "request_parser_dynamic.h"
#include "response_parser_dynamic.h"
#include "ssl_utils.h"
#include "double_table.h"
#include "write_buffer.h"
#include "cache.h"
#include "inspector.h"

#define LISTEN_BACKLOG 6
#define BUF_SIZE 3000
#define DEFAULT_PORT 80
#define TIMEOUT_SEC 10
#define DT_HINT 60

// todo consider making a network_util module to reduce clutter

int initTcpSock(int port);
int connectServer(Request req);
int readMessage(int socket, char **msgp);
int handleStdin();

int handleSSLRead(int sourceSock, SSLState state, WriteBuffer wb, fd_set *write_fd_set, Cache csh);

int handleRead(int socket, GenericState *statep, WriteBuffer wb, DTable dt, fd_set *wsp, Cache csh);

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
        errExit("[PROXY] ERROR socket binding failed");
    }

    if(listen(sock, LISTEN_BACKLOG) < 0){
        errExit("[PROXY] ERROR listening to socket failed");
    }

    return sock;
}

void queueOkConnect(int destSock, WriteBuffer wb){
    //fprintf(stderr, "ok queued\n");
    char *rspString = strdup("HTTP/1.1 200 Connection established\r\n\r\n");
    WBuf_put(wb, HTTP_TYPE, destSock, rspString, strlen(rspString));
}

int main(int argc, char **argv){
    if(argc != 2){
        errno = EINVAL;
        errExit("[PROXY] ERROR");
    }
    int port = (int)strtol(argv[1], NULL, 10);
    int mSock = initTcpSock(port);

    fd_set active_read_set, active_write_set, read_fd_set, write_fd_set;

    FD_ZERO(&active_read_set);
    FD_ZERO(&active_write_set);
    FD_SET(mSock, &active_read_set);
    FD_SET(STDIN_FILENO, &active_read_set);

    struct timeval timeSetting;
    timeSetting.tv_sec  = TIMEOUT_SEC;
    timeSetting.tv_usec = 0;
    struct timeval timeout = timeSetting;

    SSL_CTX *ctx = initCTX();
    initSSLUtils();
    initInspector();

    DTable dt = DTable_new(DT_HINT);
    WriteBuffer wb = WBuf_new(DT_HINT);
    Cache csh = cache_new(DT_HINT);

    int remaining, n;
    WriteEntry we;

    SSLState sslState;

    printf("[PROXY] Server running on address %d port %d\n", INADDR_ANY, port);
    while(true){
        read_fd_set = active_read_set;
        write_fd_set = active_write_set;

        n = select(FD_SETSIZE, &read_fd_set, &write_fd_set, NULL, &timeout);
        // fprintf(stderr, "[PROXY] STANDING BY\n");

        if(n < 0){
            errExit("[PROXY] ERROR on select");
        }else if(n == 0){
            timeout = timeSetting;
            fprintf(stderr, "[PROXY] STANDING BY...\n");
            /* Do something periodic like cleaning up the cache, closing connections, or sth */

        }else{
            for(int i = 0; i < FD_SETSIZE; i++){
                if(FD_ISSET(i, &read_fd_set)){
                    if(i == mSock){
                        int newSock = accept(mSock, NULL, NULL);
                        if(newSock < 0){
                            fprintf(stderr, "[PROXY] ERROR new connection accept failed, returned %d\n", newSock);
                            /* If accept raises errors we just keep calm and
                               carry on */
                            continue;
                        }
                        FD_SET(newSock, &active_read_set);
                    }else if(i == STDIN_FILENO){
                        /* handles stdin for debugging and stuff */

                        // for (int j = 0; j < FD_SETSIZE; j++) {
                        //     if(FD_ISSET(j, &active_read_set))
                        //         printf("%d is in active read set\n", j);
                        //     if(FD_ISSET(j, &active_write_set))
                        //     printf("%d is in active write set\n", j);
                        // }
                        handleStdin();
                    }else if((sslState = DTable_get(dt, i)) != NULL && sslState->type == SSL_TYPE){
                        /* all active SSL connections go here */
                        int err;
                        if((err = handleSSLRead(i, sslState, wb, &active_write_set, csh)) != SSL_ERROR_NONE){
                            int serverSock = SSL_get_fd(sslState->serverSSL);
                            int clientSock = SSL_get_fd(sslState->clientSSL);
                            switch (err) {
                                case SSL_ERROR_ZERO_RETURN:
                                    if(serverSock == i){
                                        SSL_shutdown(sslState->clientSSL);
                                    }else{
                                        SSL_shutdown(sslState->serverSSL);
                                    }
                                    // fprintf(stderr, "[PROXY] SSL ZERO_RETURN, normal shutdown\n");
                                    break;
                                case SSL_ERROR_SYSCALL:
                                case SSL_ERROR_SSL:
                                    fprintf(stderr, "[PROXY] SSL SSL_ERROR, closing connection\n");
                                    break;
                                default:
                                    fprintf(stderr, "[PROXY] SSL UNKNOWN ERROR when reading SSL: %d\n", err);
                            }
                            fprintf(stderr, "[PROXY] Closing SSL Connection %d >--//--< %d\n", clientSock, serverSock);
                            close(serverSock);
                            close(clientSock);
                            FD_CLR(serverSock, &active_read_set);
                            FD_CLR(clientSock, &active_read_set);
                            FD_CLR(serverSock, &active_write_set);
                            FD_CLR(clientSock, &active_write_set);
                            SSLState ss = DTable_remove(dt, clientSock, serverSock);

                            if(ss->request != NULL){
                                if(!cache_add(csh, ss->request, ss->response)){
                                    /* rejected by cache, freeing response */
                                    responseFree(ss->response);
                                }
                            }
                            requestFree(ss->request);
                            free(ss);
                        }
                    }else{
                        GenericState state;
                        int destSock;
                        if((destSock = handleRead(i, &state, wb, dt, &active_write_set, csh)) < 0){
                            // todo close connection on the other size as well
                            GenericState state = DTable_get(dt, i);
                            if(state == NULL){
                                fprintf(stderr, "[PROXY] Closing null state from %d\n", i);
                                close(i);
                                FD_CLR(i, &active_read_set);
                                FD_CLR(i, &active_write_set);
                                WBuf_remove(wb, i);
                                continue;
                            }
                            int clientSock, serverSock;
                            PlainState ps = (PlainState) state;
                            clientSock = ps->clientSock;
                            serverSock = ps->serverSock;
                            fprintf(stderr, "[PROXY] Closing PLAIN Connection %d >--//--< %d\n", clientSock, serverSock);

                            /*
                                client is probably done
                                if cacheable, insert cache here - Plain case
                            */
                            if(!cache_add(csh, ps->request, ps->response)){
                                /* rejected by cache, freeing response */
                                responseFree(ps->response);
                            }
                            
                            DTable_remove(dt, clientSock, serverSock);
                            // requestFree(ps->request);    /* Freeing this causes issue?? */
                            free(ps);

                            close(clientSock);
                            close(serverSock);
                            FD_CLR(clientSock, &active_read_set);
                            FD_CLR(serverSock, &active_read_set);
                            FD_CLR(clientSock, &active_write_set);
                            FD_CLR(serverSock, &active_write_set);
                            WBuf_remove(wb, clientSock);
                            WBuf_remove(wb, serverSock);
                        }else if(state != NULL){
                            /* Non null states indicate a new connection */
                            /* Only setting up destination socket to write set, as connection still ongoing */
                            FD_SET(destSock, &active_write_set);
                            FD_CLR(i, &active_read_set);
                            DTable_put(dt, i, destSock, state);
                        }else{
                            /* existing connections */
                            FD_SET(destSock, &active_write_set);
                        }
                    }
                }else if(FD_ISSET(i, &write_fd_set)){
                    PlainState state;
                    if((we = WBuf_get(wb, i, &remaining)) != NULL){
                        if(remaining == 0){
                            FD_CLR(i, &active_write_set);
                        }
                        handleWrite(i, we, dt);
                    }else if((state = DTable_get(dt, i)) != NULL && state->state == SERVER_CONNECT){
                        /* checking on ongoing connects */
                        /* ongoing connections are only in write_fd_set, not in WB, and has plain state for all types */
                        int err;
                        size_t errlen = sizeof(int);
                        getsockopt(i, SOL_SOCKET, SO_ERROR, &err, (socklen_t*) &errlen);
                        if(err != 0){
                            /* connect failed */
                            fprintf(stderr, "[PROXY] Failed to connect to socket %d\n", i);
                            close(state->clientSock);
                            close(state->serverSock);
                            FD_CLR(i, &active_write_set);
                            continue;
                        }

                        const int flags = fcntl(state->serverSock, F_GETFL, 0);
                        fcntl(state->serverSock, F_SETFL, flags ^ O_NONBLOCK);
                        FD_SET(state->serverSock, &active_read_set);
                        FD_SET(state->serverSock, &active_write_set);
                        FD_SET(state->clientSock, &active_read_set);
                        FD_SET(state->clientSock, &active_write_set);
                        if (state->type == SSL_TYPE) {
                            /* CONNECT request: setting up records for SSL connection */
                            SSLState sslState = initSSLState(state->clientSock, state->serverSock, ctx);
                            sslState->request = state->request;
                            fprintf(stderr, "[PROXY] SSL server connected %i ---> %d\n", state->clientSock, state->serverSock);
                            DTable_remove(dt, state->clientSock, state->serverSock);
                            DTable_put(dt, state->clientSock, state->serverSock, sslState);
                            queueOkConnect(state->clientSock, wb);
                            free(state);
                        }else{
                            /* plain HTTP, with write queued */
                            state->state = CLIENT_READ;
                            char *msg;
                            int msgLen;
                            Response rsp;
                            if((rsp = cache_get(csh, state->request, NULL)) != NULL){
                                /* Check if applicable for inspection here as well */
                                if(responseStoreForward(rsp)){
                                    inspectResponse(rsp);
                                }
                                msgLen = responseToString(rsp, &msg);
                                WBuf_put(wb, HTTP_TYPE, state->clientSock, msg, msgLen);

                            }else{
                                msgLen = requestToString(state->request, &msg);
                                WBuf_put(wb, HTTP_TYPE, state->serverSock, msg, msgLen);
                            }
                            DTable_remove(dt, state->clientSock, state->serverSock);
                            DTable_put(dt, state->clientSock, state->serverSock, state);
                            fprintf(stderr, "[PROXY] PLAIN server connected %i ---> %d\n", state->clientSock, state->serverSock);
                        }
                    }else{
                        FD_CLR(i, &active_write_set);
                    }
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
            fprintf(stderr, "[PROXY] ERROR when writing: no DTable entry for %d\n", destSock);
            return -1;
        }
        SSL *destSSL;
        if(SSL_get_fd(state->serverSSL) == destSock){
            destSSL = state->serverSSL;
        }else{
            destSSL = state->clientSSL;
        }
        // fprintf(stderr, "[PROXY] Writing to socket %d (ssl), %d bytes\n%s\n", destSock, we->msgLen, we->message);
        stat = SSL_write(destSSL, we->message, we->msgLen);
    }else{
        // fprintf(stderr, "[PROXY] Writing to socket %d (plain) %d bytes\n%s\n", destSock, we->msgLen, we->message);
        stat = write(destSock, we->message, we->msgLen);
    }
    free(we->message); /* This may cause issues (?) */
    free(we);
    return stat;
}

int handleStdin(){
    char buffer[BUF_SIZE];
    int len = read(STDIN_FILENO, buffer, BUF_SIZE);
    buffer[len] = '\0';
    
    if(strncmp(buffer, "--owo", 5) == 0){
        inspectToggleOptions(OWO, NULL);
    }else if(strncmp(buffer, "--blacklist", 11) == 0){
        inspectToggleOptions(BLACKLIST, buffer + 12);
    }else if(buffer[0] == 'q'){
        /* graceful termination option */
    }else{
        fprintf(stderr, "[PROXY] ERROR: %s is not a recognized input\n", buffer);
    }
    return 0;
}

/* returns a SSL error enum */
int handleSSLRead(int sourceSock, SSLState state, WriteBuffer wb, fd_set *wsp, Cache csh){
    if(state->state == CLIENT_CONNECT){
        generateCerts(&(state->clientSSL), state->serverSSL);
        SSL_accept(state->clientSSL);
        state->state = STANDBY;
        /* Removing the request parsed from state, as it would be a CONNECT request */
        requestFree(state->request);
        state->request = NULL;
        return SSL_ERROR_NONE;
    }

    // fprintf(stderr, "Message from %d\n", sourceSock);
    bool holdResponse = false;
    SSL *source;
    SSL *dest;
    if(SSL_get_fd(state->clientSSL) == sourceSock){
        /* incoming message is reuqest */
        if(state->state == SERVER_READ){
            /* Clear out lingering invalid responses */
            if(!responseComplete(state->response, NULL)){
                responseFree(state->response);
            }
            requestFree(state->request);
            state->request = NULL;
            state->response = NULL;
        }
        state->state = CLIENT_READ;
        source = state->clientSSL;
        dest = state->serverSSL;
    }else{
        state->state = SERVER_READ;
        source = state->serverSSL;
        dest = state->clientSSL;
    }
    char *msg;
    int bytes = readSSLMessage(source, &msg);

    // fprintf(stderr, "Recieved SSL (%d) from %d\n", bytes, sourceSock);

    if(bytes <= 0){
        return SSL_get_error(source, bytes);
    }

    if(state->state == SERVER_READ){
        /* response */
        if(state->response == NULL){
            state->response = responseNew(msg, bytes);
        }else{
            responseAppendBody(&(state->response), msg, bytes);
        }
        holdResponse = responseStoreForward(state->response);

        if(responseComplete(state->response, NULL)){
            // fprintf(stderr, "SSL - Response Complete\n");
            cache_add(csh, state->request, state->response);

            if(holdResponse){
                holdResponse = false;
                inspectResponse(state->response);
                free(msg);
                bytes = responseToString(state->response, &msg);
                responseFree(state->response);
                state->response = NULL;
            }
        }
    }else{
        if(state->request != NULL){
            /* new, subsequent request from client, clear out old request/responses */
            if(!state->fromCache){
                responseFree(state->response);
                state->response = NULL;
            }
            requestFree(state->request);
            state->request = NULL;
        }
        state->request = requestNew(msg, bytes);

        state->response = cache_get(csh, state->request, NULL);
        if(state->response != NULL){
            state->fromCache = true;
            if(responseStoreForward(state->response)){
                inspectResponse(state->response);
            }
             
            free(msg);
            bytes = responseToString(state->response, &msg);
            dest = state->clientSSL;
        }
    }


    /* Check if message is a response, and check if its store forward */
    if(!holdResponse){
        WBuf_put(wb, SSL_TYPE, SSL_get_fd(dest), msg, bytes);
        FD_SET(SSL_get_fd(dest), wsp);
    }

    return SSL_ERROR_NONE;
}

// returns -1 if error occurs, else 0
// returns positive value if write is queued

//use states for all connection
/* Only handles plain HTTP connections, although can be combined with handleSSLRead with some effort */
int handleRead(int sourceSock, GenericState *statep, WriteBuffer wb, DTable dt, fd_set *wsp, Cache csh){
    char *incoming = NULL;
    int n = readMessage(sourceSock, &incoming);
    if(n == 0){
        return -1;
    }else if(n < 0){
        fprintf(stderr, "[PROXY] ERROR when reading from socket %d\n", sourceSock);
        return -1;
    }

    // fprintf(stderr, "Received (%d) from %d\n", n, sourceSock);

    bool holdResponse = false;
    *statep = NULL;
    GenericState state = DTable_get(dt, sourceSock);
    if(state == NULL){
        /* Fresh connection; only requests possible */
        /* First request of a plain HTTP request doesn't query the cache */

        Request req = requestNew(incoming, n);
        if(req == NULL){
            fprintf(stderr, "[PROXY] ERROR when parsing request\n");
            free(incoming);
            return -1;
        }
        int destSock = connectServer(req);
        if(destSock < 0){
            free(incoming);
            requestFree(req);
            return -1;
        }

        /* Creating a temporary state while connect is still ongoing */
        *statep = (GenericState) initPlainState(sourceSock, destSock);
        if(requestMethod(req) == CONNECT){
            (*statep)->type = SSL_TYPE;
        }
        (*statep)->state = SERVER_CONNECT;
        (*statep)->request = req;

        free(incoming);
        return destSock;
    }else{
        /* Existing HTTP connections */
        PlainState ps = (PlainState) state;
        int destSock;
        if(ps->clientSock == sourceSock){
            /* Incoming is a request */
            Request newReq = requestNew(incoming, n);
            if(ps->state == SERVER_READ){
                if(state->request != NULL){
                    /* new, subsequent request from client, clear out old request/responses */
                    if(!state->fromCache){
                        responseFree(state->response);
                        requestFree(state->request);
                    }
                    state->response = NULL;
                    state->request = NULL;
                }

                ps->response = cache_get(csh, newReq, NULL);
                if(ps->response != NULL){
                    /* content inspection here as well */
                    ps->fromCache = true;
                    char *rspStr;
                    int len = responseToString(ps->response, &rspStr);
                    WBuf_put(wb, HTTP_TYPE, sourceSock, rspStr, len);
                    FD_SET(sourceSock, wsp);
                    return sourceSock;
                }
                ps->fromCache = false;
            }
            ps->request = newReq;
            ps->state = CLIENT_READ;
            destSock = ps->serverSock;
        }else{
            /* Incoming is response */
            if(state->response == NULL){
                state->response = responseNew(incoming, n);
            }else{
                responseAppendBody(&(state->response), incoming, n);
            }
            /* check here if response is complete; if so, check store forward, and add to write buffer it true */
            
            holdResponse = responseStoreForward(state->response);
            int remLen;
            if(responseComplete(state->response, &remLen)){


                cache_add(csh, state->request, state->response);
                if(holdResponse){    
                    holdResponse = false;    
                    inspectResponse(state->response);
                
                    free(incoming);
                    n = responseToString(state->response, &incoming);
                } 

                responseFree(state->response);
                state->response = NULL;
            }
            ps->state = SERVER_READ;
            destSock = ps->clientSock;
        }
        /* somewhere check if incoming is a response, and if response is store forward */
        if(!holdResponse){
            WBuf_put(wb, HTTP_TYPE, destSock, incoming, n);
            FD_SET(destSock, wsp);
        }
        return destSock;
    }
}

//returns socket if successful, else -1
int connectServer(Request req){
    /* creating outbout socket, socket set to nonblocking before connecting */
    int outSock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(outSock < 0){
        errExit("[PROXY] ERROR failed to create outbound socket");
    }

    /* getting host via DNS */
    char *host = requestHost(req);
    struct hostent *server;
    if(host == NULL){
        char uri[BUF_SIZE];
        int len, port;
        sscanf(requestUri(req), "%[^:]%n:%d", uri, &len, &port);
        uri[len] = '\0';
        server = gethostbyname(uri);
    }else{
        server = gethostbyname(host);
    }
    if(server == NULL){
        fprintf(stderr, "[PROXY] ERROR cannot find host with name [%s]\n", host);
        char *reqStr;
        requestToString(req, &reqStr);
        //fprintf(stderr, "MSG:\n%s\n", reqStr);
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
        // fprintf(stderr, "Connection using custom port %d\n", hostPort);
        serveraddr.sin_port = htons(hostPort);
    }

    /* connect with server */
    if(connect(outSock, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
        switch (errno) {
            case EINPROGRESS:
                fprintf(stderr, "[PROXY] Started connecting to %d...\n", outSock);
                break;
            default:
                perror("[PROXY] ERROR connecting");
                return -1;
        }
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
        return -1;
    }

    msglen += n;

    while(n == BUF_SIZE){
        char buffest[BUF_SIZE];
        bzero(buffest, BUF_SIZE);
        n = read(socket, buffest, BUF_SIZE);
        if(n < 0){
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
