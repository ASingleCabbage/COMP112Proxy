#include "ssl_utils.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <limits.h>
#include <errno.h>

#define BUF_SIZE 1024

SSLState initSSLState(int clientSock, int serverSock, SSL_CTX *ctx){
    SSLState state = calloc(1, sizeof(struct ssl_connection));
    state->clientSSL = SSL_new(ctx);
    state->serverSSL = SSL_new(ctx);
    SSL_set_fd(state->clientSSL, clientSock);
    SSL_set_fd(state->serverSSL, serverSock);
    SSL_connect(state->serverSSL);

    state->type = SSL_TYPE;
    state->state = CLIENT_CONNECT;

    return state;
}

PlainState initPlainState(int clientSock, int serverSock){
    PlainState state = calloc(1, sizeof(struct plain_connection));
    state->clientSock = clientSock;
    state->serverSock = serverSock;
    state->type = HTTP_TYPE;
    state->state = CLIENT_CONNECT;
    return state;
}

void sslErrorExit(){
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int forwardEncrypted(int destSock, int srcSock){
    char buffer[BUF_SIZE];
    int n = read(srcSock, buffer, BUF_SIZE);

    if(n == 0){
        return -1;
    }else if(n < 0){
        fprintf(stderr, "forwardEncrypted: Error when reading from socket %d\n", n);
    }

    n = write(destSock, buffer, n);
    if(n == 0){
        return -1;
    }else if(n < 0){
        fprintf(stderr, "forwardEncrypted: Error when writing to socket %d\n", n);
        return -1;
    }
    return 0;
}

SSL_CTX *initCTX(){
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *meth = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if(ctx == NULL){
        sslErrorExit();
    }
    return ctx;
}

void loadCerts(SSL_CTX *ctx, char *certFile, char *keyFile){
    if(SSL_CTX_use_certificate_chain_file(ctx, certFile) <= 0){
        sslErrorExit();
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0){
        sslErrorExit();
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Certificate error\n");
        exit(EXIT_FAILURE);
    }
}

int readSSLMessage(SSL *ssl, char ** msgp){
    char *buffer = calloc(BUF_SIZE + 1, 1);
    int bufsize = BUF_SIZE;
    int msglen = 0;
    int n = SSL_read(ssl, buffer, BUF_SIZE);
    if(n < 0){
        fprintf(stderr, "ERROR when reading SSL message\n");
        return n;
    }
    fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);

    msglen += n;
    while(BUF_SIZE == n){
        char buffest[BUF_SIZE];
        fprintf(stderr, "Trying to read\n");
        n = SSL_read(ssl, buffest, BUF_SIZE);

        if(n < 0){
            fprintf(stderr, "ERROR when reading SSL message - subsequent reads\n");
            return n;
        }

        fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);
        bufsize += BUF_SIZE;
        buffer = realloc(buffer, bufsize + 1);
        memcpy(buffer + msglen, buffest, n);
        msglen += n;
    }
    buffer[msglen] = '\0';
    *msgp = buffer;
    return msglen;
}
