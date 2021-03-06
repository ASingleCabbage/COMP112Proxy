#ifndef HTTP_HEADER
#define HTTP_HEADER

#include <stdbool.h>
typedef enum {GET, CONNECT, POST, OTHER} httpMethod;

typedef struct Header{
    char *name;
    char *value;
    struct Header *next;
} *Header;

Header dupHeadList(Header head);

Header getHeader(Header head, char *fieldname);

/* strings passed in add and appendHeader are freeable afterwards */

/* Replaces existing if exists */
void addHeader(Header *headp, char *name, char *value);

void removeHeader(Header *headp, char *name);

/* Appends values if field already exists, else create a new header entry */
void appendHeader(Header *headp, char *name, char *value);

bool headerHasValue(Header h, char *target, char *delim);

void freeHeader(Header head);

int toStringHeader(Header h, char **strp);

#endif /* HTTP_HEADER */
