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

#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#include<assert.h>
#include<table.h>
#include "pcg_basic.h"

#define BUF_SIZE 1500
#define TABLE_HINT 300

void initSSLUtils(){
    srand(time(NULL));
    pcg32_srandom(rand(), rand());
}

SSLState initSSLState(int clientSock, int serverSock, SSL_CTX *ctx){
    SSLState state = calloc(1, sizeof(struct ssl_connection));
    state->clientSSL = SSL_new(ctx);
    state->serverSSL = SSL_new(ctx);
    state->request = NULL;
    state->response = NULL;
    SSL_set_fd(state->clientSSL, clientSock);
    SSL_set_fd(state->serverSSL, serverSock);
    SSL_connect(state->serverSSL);
    state->type = SSL_TYPE;
    state->state = CLIENT_CONNECT;
    return state;
}

void showFields(X509 *cert){
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    fprintf(stderr, "CERTIFICATE:\n%s\n%s\n", subj, issuer);
}

void copy_ext(X509 *cert, X509 *sourceCert, int nid){
    int crit;
    void *san = X509_get_ext_d2i(sourceCert, nid, &crit, NULL);

    X509_add1_ext_i2d(cert, nid, san, crit, X509V3_ADD_REPLACE);
}

void generateCerts(SSL **sslp, SSL *source){
    assert(source != NULL);
    assert(*sslp != NULL);

    X509 *sourceX509 = SSL_get_peer_certificate(source); //do we need to repackage the thing?
    if(sourceX509 == NULL){
        return;
    }

    FILE *pkeyFile = fopen("server.key", "r");
    RSA *rootRsa = PEM_read_RSAPrivateKey(pkeyFile , NULL, 0, NULL);
    fclose(pkeyFile);
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    EVP_PKEY *rkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rkey, rootRsa);

    X509 *cert = X509_new();
    uint64_t serial = pcg32_random();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    X509_gmtime_adj(X509_get_notBefore(cert), -30);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    X509_set_pubkey(cert, pkey);
    X509_NAME *subject = X509_NAME_dup(X509_get_subject_name(sourceX509));
    X509_set_subject_name(cert, subject);

    X509_NAME * issuer = X509_get_issuer_name(cert);
    X509_NAME_add_entry_by_txt(issuer, "C",  MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "ST",  MBSTRING_ASC, (unsigned char *)"Massachusetts", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "L",  MBSTRING_ASC, (unsigned char *)"Medford", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "O",  MBSTRING_ASC, (unsigned char *)"Totally not evil inc", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "OU",  MBSTRING_ASC, (unsigned char *)"Web division", -1, -1, 0);
    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (unsigned char *)"Big brother", -1, -1, 0);

    copy_ext(cert, sourceX509, NID_subject_alt_name);

    X509_sign(cert, rkey, EVP_sha256());

    SSL_use_certificate(*sslp, cert);
    SSL_use_PrivateKey(*sslp, pkey);
    if (!SSL_check_private_key(*sslp)){
        fprintf(stderr, "Generate Certificate error\n");
        exit(EXIT_FAILURE);
    }

    FILE *out = fopen("check.crt","w");
    PEM_write_X509(out, cert);
    fclose(out);
}

void showCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);							/* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);							/* free the malloc'ed string */
        X509_free(cert);					/* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

PlainState initPlainState(int clientSock, int serverSock){
    PlainState state = calloc(1, sizeof(struct plain_connection));
    state->clientSock = clientSock;
    state->serverSock = serverSock;
    state->request = NULL;
    state->response = NULL;
    state->type = HTTP_TYPE;
    state->state = CLIENT_CONNECT;
    return state;
}

// void attachPartial(GenericState gs, char *msg, int len){
//     if(gs->partial == NULL){
//         gs->partial = msg;
//         gs->partialLen = len;
//     }else{
//         gs->partial = realloc(gs->partial, gs->partialLen + len + 1);
//         memcpy(gs->partial + gs->partialLen, msg, len);
//         gs->partialLen += len;
//         (gs->partial)[gs->partialLen] = '\0';
//     }
// }
//
// void clearPartial(GenericState gs){
//     gs->partialLen = 0;
//     free(gs->partial);
//     gs->partial = NULL;
// }

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
        ERR_print_errors_fp(stderr);
        return n;
    }
    // fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);

    msglen += n;
    while(BUF_SIZE == n){
        char buffest[BUF_SIZE];
        // fprintf(stderr, "Trying to read\n");
        n = SSL_read(ssl, buffest, BUF_SIZE);

        if(n < 0){
            fprintf(stderr, "ERROR when reading SSL message - subsequent reads\n");
            ERR_print_errors_fp(stderr);
            return n;
        }

        // fprintf(stderr, "reading %d/%d bytes\n", n, bufsize);
        bufsize += BUF_SIZE;
        buffer = realloc(buffer, bufsize + 1);
        memcpy(buffer + msglen, buffest, n);
        msglen += n;
    }
    buffer[msglen] = '\0';
    *msgp = buffer;
    return msglen;
}
