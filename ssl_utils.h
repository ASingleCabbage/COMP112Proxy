#ifndef SSL_UTILS
#define SSL_UTILS value

#include <sys/socket.h>
#include <openssl/ssl.h>

//move this to general purpose network_utils.h?
typedef enum{ HTTP_TYPE, SSL_TYPE } connectType;
typedef enum{ IO_COMPLETE, IO_READY, IO_WAIT, IO_CLOSE, IO_ERROR} sslIOState;

typedef enum{ STANDBY, CLIENT_READ, CLIENT_WRITE, SERVER_READ, SERVER_WRITE, CLIENT_CONNECT } connectState;
typedef enum{ UNKNOWN = INT_MIN } partialRemain;    //todo since we only have one entry might want to swap it to a #define

struct ssl_connection{
    connectType type;
    connectState state;
    SSL *clientSSL;
    SSL *serverSSL;
    char *partial;
    int partialLen;
    int remainLen;
    time_t lastTransmit;    //used to close timed out connections
};

typedef struct ssl_connection *SSLState; //rename for all types of connection

struct plain_connection{
    connectType type;
    connectState state;
    int clientSock;
    int serverSock;
    char *partial;
    int partialLen;
    int remainLen;
    time_t lastTransmit;
};

typedef struct plain_connection *PlainState; //rename for all types of connection

typedef struct {
    connectType type;
    connectState state;
} *GenericState;

void generateCerts(SSL **sslp, SSL *source);

void ShowCerts(SSL* ssl);

SSLState initSSLState(int clientSock, int serverSock, SSL_CTX *ctx);

PlainState initPlainState(int clientSock, int serverSock);

int forwardEncrypted();

SSL_CTX *initCTX();

void loadCerts(SSL_CTX *ctx, char *certFile, char *keyFile);

int readSSLMessage(SSL *ssl, char **msgp);

sslIOState handleSSLIO(SSL *ssl, int ret, struct timeval *timeout);


#endif /* SSL_UTILS */
