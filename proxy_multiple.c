/*
    Multiple client proxy
    Sequential benchmark: 9064ms
    Current focus:
        Integrating caching functions
            --> bugs
                    response header has memory allocated by request ?????
            --> edge cases: uri is "/" when its the same as previous (abs_path mode)


        Store and forward mode and determining which response types to use that
        Modify transfer encoding (chunked --> plain) headers in the tostring function
        New module focusing on Content Inspection functions
    Pending features:
        Partial handling
            request is assumed to be readable all at once -> no exceptions yet
            Partial is catched through the Response object
            Partial catching is done for all --> enable based on resource type?
        Text replacement
        Cacheing
        Domain blacklisting
        Content decoding
        Debugging mode

    General improvements
        [COMPLETED] request and response parser overhaul for flexibility
                        --> parsing all fields instead of
                            cache control related only
        [COMPLETED BUT BUGS] partial handling implementation complete
        [COMPLETED] sockets are set to non-blocking during connect, hopefully preventing
                    large amount of connect slowing down the proxy

    Preformance improvemnets
        look into multithreading? <--- no fuck that
    Notes:
        SSL Certificates, needs some sort of caching as well...
        Memory allocations and frees are all over the freakin place
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

#define LISTEN_BACKLOG 6
#define BUF_SIZE 3000
#define DEFAULT_PORT 80
#define TIMEOUT_SEC 60
#define DT_HINT 60

// todo consider making a network_util module to reduce clutter

int initTcpSock(int port);
int connectServer(Request req);
int readMessage(int socket, char **msgp);
int handleStdin();

int handleSSLRead(int sourceSock, SSLState state, WriteBuffer wb, fd_set *write_fd_set, Cache csh);

int handleRead(int socket, GenericState *statep, SSL_CTX *ctx, WriteBuffer wb, DTable dt, Cache csh);

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

void writeLog(char *msg, char *mode){
    FILE *file = fopen("log.txt", mode);
    fprintf(file, msg);
    fclose(file);
}

int main(int argc, char **argv){
    if(argc != 2){
        errno = EINVAL;
        errExit("ERROR");
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

    DTable dt = DTable_new(DT_HINT);
    WriteBuffer wb = WBuf_new(DT_HINT);
    Cache csh = cache_new(DT_HINT);

    int remaining, n;
    WriteEntry we;

    SSLState sslState;

    printf("Server running on address %d port %d\n", INADDR_ANY, port);
    while(true){
        // fprintf(stderr, "Main loop\n");

        read_fd_set = active_read_set;
        write_fd_set = active_write_set;

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
                        FD_SET(newSock, &active_read_set);
                    }else if(i == STDIN_FILENO){
                        /* handles stdin for debugging and stuff */
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
                            // fprintf(stderr, "Clearing SSL %d %d from set\n", serverSock, clientSock);
                            FD_CLR(serverSock, &active_read_set);
                            FD_CLR(clientSock, &active_read_set);
                            FD_CLR(serverSock, &active_write_set);
                            FD_CLR(clientSock, &active_write_set);
                            SSLState ss = DTable_remove(dt, clientSock, serverSock);

                            /*
                                if cacheable, insert cache here; SSL case
                            */
                            if(!cache_add(csh, ss->response, requestUri(ss->request))){
                                responseFree(ss->response);
                            }

                            requestFree(ss->request);
                            free(ss);
                        }
                    }else{
                        GenericState state;
                        int destSock;
                        if((destSock = handleRead(i, &state, ctx, wb, dt, csh)) < 0){
                            fprintf(stderr, "Closing connection %d\n", i);
                            // todo close connection on the other size as well
                            GenericState state = DTable_get(dt, i);
                            if(state == NULL){
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
                            /*
                                client is probably done
                                if cacheable, insert cache here - Plain case
                            */
                            if(!cache_add(csh, ps->response, requestUri(ps->request))){
                                responseFree(ps->response);
                            }
                            requestFree(ps->request);
                            free(ps);

                            assert(DTable_get(dt, clientSock) == NULL);
                            assert(DTable_get(dt, serverSock) == NULL);
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
                        getsockopt(i, SOL_SOCKET, SO_ERROR, &err, &errlen);
                        if(err != 0){
                            /* connect failed */
                            fprintf(stderr, "Failed to connect to socket %d\n", i);
                            close(state->clientSock);
                            close(state->serverSock);
                            FD_CLR(i, &active_write_set);
                            continue;
                        }

                        const int flags = fcntl(state->serverSock, F_GETFL, 0);
                        fcntl(state->serverSock, F_SETFL, flags ^ O_NONBLOCK);

                        FD_SET(state->serverSock, &active_read_set);
                        FD_SET(state->clientSock, &active_read_set);
                        FD_SET(state->serverSock, &active_write_set);
                        FD_SET(state->clientSock, &active_write_set);
                        if (state->type == SSL_TYPE) {
                            /* CONNECT request: setting up records for SSL connection */
                            SSLState sslState = initSSLState(state->clientSock, state->serverSock, ctx);
                            sslState->request = state->request;
                            fprintf(stderr, "SSL server connected %i ---> %d\n", state->clientSock, state->serverSock);
                            DTable_remove(dt, state->clientSock, state->serverSock);
                            DTable_put(dt, state->clientSock, state->serverSock, sslState);
                            queueOkConnect(state->clientSock, wb);
                            free(state);
                        }else{
                            /* plain HTTP, with write queued */
                            state->state = CLIENT_READ;

                            char *msg;
                            int msgLen = requestToString(state->request, &msg);
                            WBuf_put(wb, HTTP_TYPE, state->serverSock, msg, msgLen);
                            DTable_put(dt, state->clientSock, state->serverSock, state);
                            fprintf(stderr, "PLAIN server connected %i ---> %d\n", state->clientSock, state->serverSock);
                        }
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
            fprintf(stderr, "HANDLEWRITE: no DTable entry for %d\n", destSock);
            return -1;
        }
        SSL *destSSL;
        if(SSL_get_fd(state->serverSSL) == destSock){
            destSSL = state->serverSSL;
        }else{
            destSSL = state->clientSSL;
        }
        // fprintf(stderr, "Writing to socket %d (ssl)\n", destSock);
        stat = SSL_write(destSSL, we->message, we->msgLen);
    }else{
        // fprintf(stderr, "Writing to socket %d (plain)\n", destSock);
        stat = write(destSock, we->message, we->msgLen);
    }
    //free(we->message);
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
int handleSSLRead(int sourceSock, SSLState state, WriteBuffer wb, fd_set *wsp, Cache csh){
    if(state->state == CLIENT_CONNECT){
        generateCerts(&(state->clientSSL), state->serverSSL);
        SSL_accept(state->clientSSL);
        state->state = CLIENT_READ;
        /* Removing the request parsed from state, as it would be a CONNECT request */
        requestFree(state->request);
        state->request = NULL;
        return SSL_ERROR_NONE;
    }

    // fprintf(stderr, "Message from %d\n", sourceSock);
    SSL *source;
    SSL *dest;
    if(SSL_get_fd(state->clientSSL) == sourceSock){
        if(state->state == SERVER_READ){
            /* Subsequent requests on same connection; clearing out old request for new one */
            /* Cache insertion from here */
            state->state = CLIENT_READ;

            if(responseComplete(state->response, NULL)){
                if(responseComplete(state->response, NULL)){
                    if(!cache_add(csh, state->response, requestUri(state->request))){
                        responseFree(state->response);
                    }
                }else{
                    responseFree(state->response);
                }
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
    if(bytes <= 0){
        return SSL_get_error(source, bytes);
    }


    if(state->state == SERVER_READ){
        if(state->response == NULL){
            state->response = responseNew(msg, bytes);
        }else{
            responseAppendBody(&(state->response), msg, bytes);
        }
    }else{
        if(state->request != NULL){
            responseFree(state->response);
            state->response = NULL;
            requestFree(state->request);
            state->request = NULL;
            /*
                URL available for SSL connections here
                query cache and add responses to write buffer
            */
        }
        state->request = requestNew(msg, bytes);
    }
    // fprintf(stderr, "Add to write buffer\n");
    WBuf_put(wb, SSL_TYPE, SSL_get_fd(dest), msg, bytes);
    FD_SET(SSL_get_fd(dest), wsp);
    return SSL_ERROR_NONE;
}

// returns -1 if error occurs, else 0
// returns positive value if write is queued

//use states for all connection
int handleRead(int sourceSock, GenericState *statep, SSL_CTX *ctx, WriteBuffer wb, DTable dt, Cache csh){
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
        /*
            Query cache and retrieve here
            If exists in cache, retrieve and add to write buffer,
            and manually close one sided connection
            Should work for SSL connections as well, but an OK response should be
            sent first. Although we do have to re-encrypt and possibly regenerate
            another set of certificates -> dedicated function for SSL after cache retrieval
        */

        int destSock = connectServer(req);
        if(destSock < 0){
            free(incoming);
            requestFree(req);
            return -1;
        }

        *statep = (GenericState) initPlainState(sourceSock, destSock);
        if(requestMethod(req) == CONNECT){
            (*statep)->type = SSL_TYPE;
        }
        (*statep)->state = SERVER_CONNECT;
        (*statep)->request = req;

        free(incoming);
        return destSock;
    }else if(state->type == HTTP_TYPE){
        // fprintf(stderr, "EXISTING HTTP\n");
        PlainState ps = (PlainState) state;
        int destSock;
        if(ps->clientSock == sourceSock){
            if(ps->state == SERVER_READ){
                /* New requests after previous request has been serviced */
                /* Cache previous response, clean up state and partial, and check if new
                   request can be serivced from cache.
                 */
                if(responseComplete(ps->response, NULL)){
                    if(!cache_add(csh, ps->response, requestUri(ps->request))){
                        responseFree(ps->response);
                    }
                }else{
                    responseFree(ps->response);
                }
                requestFree(ps->request);
                ps->request = NULL;
                ps->response = NULL;

                /* Query cache */

            }else{
                fprintf(stderr, "MULTIPLE NON SSL REQUESTS\n");
            }
            ps->state = CLIENT_READ;
            destSock = ps->serverSock;
        }else{
            // attachPartial(state, incoming, n);
            if(state->response == NULL){
                state->response = responseNew(incoming, n);
            }else{
                /* Assuming headers get transfered in one chunk */
                responseAppendBody(&(state->response), incoming, n);
            }
            ps->state = SERVER_READ;
            destSock = ps->clientSock;
        }
        WBuf_put(wb, HTTP_TYPE, destSock, incoming, n);
        return destSock;
    }else{
        fprintf(stderr, "Uh oh this is not supposed to be printed (SSL)\n");
        //Existing SSL transmission: currently handled by another function
    }
    free(incoming);
    fprintf(stderr, "Uh oh this is not supposed to be printed\n");
    return -1;
}

//returns socket if successful, else -1
int connectServer(Request req){
    /* creating outbout socket, socket set to nonblocking before connecting */
    int outSock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(outSock < 0){
        errExit("ERROR failed to create outbound socket");
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
        fprintf(stderr, "ERROR cannot find host with name [%s]\n", host);
        char *reqStr;
        requestToString(req, &reqStr);
        fprintf(stderr, "MSG:\n%s\n", reqStr);
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
                fprintf(stderr, "Started connecting to %d...\n", outSock);
                break;
            default:
                perror("ERROR connecting");
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
