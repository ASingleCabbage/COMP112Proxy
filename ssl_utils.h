#ifndef SSL_UTILS
#define SSL_UTILS

#include <sys/socket.h>
#include <openssl/ssl.h>
#include "request_parser_dynamic.h"
#include "response_parser_dynamic.h"

//move this to general purpose network_utils.h?
typedef enum{ HTTP_TYPE, SSL_TYPE } connectType;

typedef enum{ STANDBY, CLIENT_READ, SERVER_READ, REQUEST_COMPLETE, CLIENT_CONNECT, SERVER_CONNECT } connectState;
typedef enum{ UNKNOWN = INT_MIN } partialRemain;    //todo since we only have one entry might want to swap it to a #define

struct ssl_connection{
    connectType type;
    connectState state;
    Request request;
    Response response;
    time_t lastTransmit;    //used to close timed out connections; not utilized
    SSL *clientSSL;
    SSL *serverSSL;
};

typedef struct ssl_connection *SSLState; //rename for all types of connection

/* todo add pointers to requests and responses */
struct plain_connection{
    connectType type;
    connectState state;
    Request request;
    Response response;
    time_t lastTransmit;    //not utilized
    int clientSock;
    int serverSock;
};

typedef struct plain_connection *PlainState; //rename for all types of connection

typedef struct {
    connectType type;
    connectState state;
    Request request;
    Response response;
    time_t lastTransmit;    //not utilized
} *GenericState;

void initSSLUtils();

void attachPartial(GenericState gs, char *msg, int len);

void clearPartial(GenericState gs);

void generateCerts(SSL **sslp, SSL *source);

void ShowCerts(SSL* ssl);

SSLState initSSLState(int clientSock, int serverSock, SSL_CTX *ctx);

PlainState initPlainState(int clientSock, int serverSock);

int forwardEncrypted();

SSL_CTX *initCTX();

void loadCerts(SSL_CTX *ctx, char *certFile, char *keyFile);

int readSSLMessage(SSL *ssl, char **msgp);


#endif /* SSL_UTILS */
