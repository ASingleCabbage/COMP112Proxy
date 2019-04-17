#ifndef WRITE_BUFFER
#define WRITE_BUFFER

#include <table.h>
#include "ssl_utils.h"

typedef struct writeEntry *WriteEntry;
typedef Table_T WriteBuffer;

struct writeEntry{
    connectType type;
    char *message;
    int destSock; //may be unnecessary as it is the key
    int msgLen;
};

WriteBuffer WBuf_new(int hint);

WriteEntry WBuf_get(WriteBuffer wb, int sock, int *backlogp);

void WBuf_put(WriteBuffer wb, connectType type, int destSock, char *msg, int len);

void WBuf_remove(WriteBuffer wb, int sock);

#endif /* WRITE_BUFFER */
