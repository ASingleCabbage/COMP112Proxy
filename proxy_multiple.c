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
#include <time.h>
#include <openssl/ssl.h>

#include "request_parser.h"
#include "response_parser.h"

#include "double_table.h"

#define LISTEN_BACKLOG 0
#define BUF_SIZE 1024
#define DEFAULT_PORT 80
#define TIMEOUT_SEC 30
#define DT_HINT 40

// todo consider making a network_util module to reduce clutter

int initTcpSock(int port);
Response getResponse(Request req);
int connectServer(Request req);
int readUntilDone(int socket, char **msgp);
int handleClient(int socket);

void errExit(char *msg){
    perror(msg);
    exit(EXIT_FAILURE);
}

int forward(int destSock, int srcSock){
    fprintf(stderr, "transmission from %d to %d\n", srcSock, destSock);

    char *buffer = calloc(BUF_SIZE, 1);
    int n = read(srcSock, buffer, BUF_SIZE);

    if(n == 0){
        fprintf(stderr, "Reading nothing from socket %d\n", n);
        return -1;
    }else if(n < 0){
        fprintf(stderr, "Error when reading from socket %d\n", n);
        return -1;
    }

    n = write(destSock, buffer, n);   //todo error handling
    if(n == 0){
        fprintf(stderr, "Writing nothing from socket %d\n", n);
        return -1;
    }else if(n < 0){
        fprintf(stderr, "Error when writing from socket %d\n", n);
        return -1;
    }
    fprintf(stderr, "Written %d bytes to %d\n", n, destSock);

    free(buffer);
    return 0;
}


int main(int argc, char **argv){
    if(argc != 2){
        errno = EINVAL;
        errExit("ERROR");
    }
    int port = (int)strtol(argv[1], NULL, 10);
    int mSock = initTcpSock(port);
    printf("Server running on address %d port %d\n", INADDR_ANY, port);

    fd_set active_fd_set, read_fd_set;

    FD_ZERO(&active_fd_set);
    FD_SET(mSock, &active_fd_set);
    FD_SET(STDIN_FILENO, &active_fd_set);

    struct timeval timeSetting;
    timeSetting.tv_sec  = TIMEOUT_SEC;
    timeSetting.tv_usec = 0;
    struct timeval timeout = timeSetting;

    DTable connections = DTable_new(DT_HINT);

    int destination;

    while(true){
        fprintf(stderr, "READY\n");

        read_fd_set = active_fd_set;

        int n = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout);

        if(n < 0){
            errExit("ERROR on select");
        }else if(n == 0){
            timeout = timeSetting;
            /* Do something periodic like cleaning up the cache or sth */
        }else{
            for(int i = 0; i < FD_SETSIZE; i++){
                if(FD_ISSET(i, &read_fd_set)){
                    if(i == mSock){
                        int newSock = accept(mSock, NULL, NULL);
                        if(newSock < 0){
                            /* If accept raises errors we just keep calm and
                               carry on */
                            continue;
                        }
                        FD_SET(newSock, &active_fd_set);
                    }else if(i == STDIN_FILENO){
                        /* handles stdin for debugging and stuff */
                        char buffer[11];
                        int len = read(STDIN_FILENO, buffer, 10);
                        buffer[len] = '\0';
                        if(buffer[0] == 'q'){
                            /* graceful termination */
                        }else if(buffer[0] == 'a'){
                            fprintf(stderr, "Active FDs: ");
                            for(int fd = 0; fd < FD_SETSIZE; fd++){
                                if(FD_ISSET(fd, &active_fd_set)){
                                    fprintf(stderr, " %d ", fd);
                                }
                            }
                            fprintf(stderr, "\n");
                        }
                    }else if((destination = DTable_get(connections, i)) != 0){
                        //Tunneling
                        fprintf(stderr, "New transmission from %d\n", i);
                        int stat = forward(destination, i);

                        if(stat == -1){
                            fprintf(stderr, "Closing connection %d\n", i);
                            close(i);
                            close(destination);
                            FD_CLR(i, &active_fd_set);
                            FD_CLR(destination, &active_fd_set);
                            DTable_remove(connections, i);
                        }
                    }else{
                        if((destination = handleClient(i)) < 0){
                            fprintf(stderr, "Closing connection %d\n", i);
                            close(i);
                            FD_CLR(i, &active_fd_set);
                        }else if(destination > 0){
                            FD_SET(destination, &active_fd_set);
                            DTable_put(connections, i, destination);
                        }
                    }
                }
            }
        }
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

int handleClient(int socket){
    char *incoming;
    int n = readUntilDone(socket, &incoming);
    if(n == 0){
        fprintf(stderr, "Reading nothing from socket %d\n", socket);
        return -1;
    }else if(n < 0){
        fprintf(stderr, "Error when reading from socket %d\n", socket);
        return -1;
    }

    Request req = requestNew(incoming, n);
    if(req == NULL){
        return -1;
    }


    char *rspString; //not actually c string format, change name?
    int rspLen;
    int retVal;
    if(requestMethod(req) == CONNECT){
        if((retVal = connectServer(req)) > 0){
            rspString = strdup("HTTP/1.1 200 Connection established\r\n\r\n");
            rspLen = strlen(rspString);
            write(socket, rspString, rspLen);   //todo error handling
        }else{
            // error at connectServer
        }
    }else{
        Response rsp = getResponse(req);
        rspLen = responseToCharAry(rsp, &rspString);
        write(socket, rspString, rspLen); //todo error handling
        retVal = 0;
        responseFree(rsp);
    }

    // if(rspLen == 0){
    //     fprintf(stderr, "Reading no reply from socket %d\n", socket);
    //     return -1;
    // }else if(rspLen < 0){
    //     fprintf(stderr, "Error when reading reply from socket %d\n", socket);
    //     return -1;
    // }

    // n = write(socket, rspString, rspLen);
    // if(n < 0){
    //     fprintf(stderr, "Error writing to client socket\n");
    //     return -1;
    // }
    // printf("written %d bytes out of %d bytes\n\n", n, rspLen);

    requestFree(req);
    free(incoming);
    return retVal;
}

Response getResponse(Request req){
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
        serveraddr.sin_port = htons(DEFAULT_PORT);
    }else{
        serveraddr.sin_port = htons(hostPort);
    }

    /* connect with server */
    if(connect(outSock, (const struct sockaddr *)&serveraddr,
               sizeof(serveraddr)) < 0){
      errExit("ERROR connecting");
    }

    char *msg;
    int len = requestToCharAry(req, &msg);

    fprintf(stderr, "CHAR ARY with length %d and msg %s\n", len, msg);


    int n = write(outSock, msg, len);
    if(n < 0){
        errExit("ERROR failed to write to outbound socket");
    }

    char *reply;
    int replen = readUntilDone(outSock, &reply);
    fprintf(stderr, "Reply received\n");
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

    return outSock;
}

/* Notice: function does memory allocation on msg */
int readUntilDone(int socket, char ** msgp){
    char *buffer = calloc(BUF_SIZE, 1);
    int bufsize = BUF_SIZE;
    int msglen = 0;
    int n = read(socket, buffer, BUF_SIZE);
    if(n < 0){
        fprintf(stderr, "ERROR failed to read from outgoing socket\n");
        return -1;
    }

    fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);

    msglen += n;

    while(n == BUF_SIZE){
        char buffest[BUF_SIZE];
        bzero(buffest, BUF_SIZE);
        n = read(socket, buffest, BUF_SIZE);
        fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);
        if(n < 0){
            fprintf(stderr, "ERROR failed to read from outgoing socket\n");
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
