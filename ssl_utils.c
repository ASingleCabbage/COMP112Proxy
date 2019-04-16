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
    // sslIOState ioState = handleSSLIO(ssl, 0, NULL);
    // fprintf(stderr, "IO state is %d\n", ioState);
    //
    // if(ioState != IO_READY && ioState != IO_COMPLETE){
    //     fprintf(stderr, "%s: ERROR 1 (type %d) failed to read from outgoing socket\n", __func__, n);
    //     return n;
    // }
    fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);

    msglen += n;
    while(BUF_SIZE == n){
        char buffest[BUF_SIZE];
        fprintf(stderr, "Trying to read\n");
        n = SSL_read(ssl, buffest, BUF_SIZE);
        // ioState = handleSSLIO(ssl, n, NULL);

        // fprintf(stderr, "IO state is %d\n", ioState);
        // if(ioState != IO_READY && ioState != IO_COMPLETE){
        //     fprintf(stderr, "%s: ERROR 2 (type %d) failed to read from outgoing socket\n", __func__, n);
        //     return n;
        // }else if(ioState == IO_COMPLETE){
        //     //same as comparing n with 0 I guess
        //     break;
        // }

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

// code adapted from https://stackoverflow.com/a/24357109
// notice: timeoutp can be mutated by the select call
// code meant for non blocking IO so may not even be applicable
sslIOState handleSSLIO(SSL *ssl, int ret, struct timeval *tp){
    fprintf(stderr, "IO HANDLER\n");
    struct timeval timeout;
    if(tp == NULL){
        timeout.tv_sec  = 0;
        timeout.tv_usec = 500;
    }else{
        timeout = *tp;
    }

    int sock = SSL_get_fd(ssl);
    int error = SSL_get_error(ssl, ret);
    fd_set sock_set;

    int n = 0;
    switch (error) {
        case SSL_ERROR_NONE:
            fprintf(stderr, "No SSL error to report\n");
            return IO_READY;
            break;
        case SSL_ERROR_WANT_READ:
        fprintf(stderr, "SSL_ERROR_WANT_READ case\n");

            do{
                FD_ZERO(&sock_set);
                FD_SET(sock, &sock_set);
                n = select(sock + 1, &sock_set, NULL, NULL, &timeout);
            }while((n < 0) && (errno == EINTR));
            if(n == 0){
                //timed out
                errno = ETIMEDOUT;
                return IO_WAIT;   //todo is this even necessary? errno might suffice
            }else{
                return IO_READY;
            }
            break;
        case SSL_ERROR_WANT_WRITE:
        fprintf(stderr, "SSL_ERROR_WANT_WRITE case\n");

            do{
                FD_ZERO(&sock_set);
                FD_SET(sock, &sock_set);
                n = select(sock + 1, NULL, &sock_set, NULL, &timeout);
            }while((n < 0) && (errno == EINTR));
            if(n == 0){
                //timed out
                errno = ETIMEDOUT;
                return IO_WAIT;
            }else{
                return IO_READY;
            }
            break;
        case SSL_ERROR_ZERO_RETURN:
            //terminate ssl (not necessary TCP)
            fprintf(stderr, "SSL connection has been closed\n");
            return IO_CLOSE;
            break;
        default:
            fprintf(stderr, "SSL IO handler: no case\n");
            if(ret == 0){
                fprintf(stderr, "SSL IO handler: determines complete\n");
                return IO_COMPLETE;
            }
            return IO_ERROR;
            //some error perhaps
    }
}
