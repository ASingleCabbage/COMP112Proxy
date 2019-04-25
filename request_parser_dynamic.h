#ifndef REQUEST_PARSER_DYNAMIC
#define REQUEST_PARSER_DYNAMIC

#include <stdbool.h>
#include <stdlib.h>
#include "http_header.h"

//seperate type for response
typedef struct request *Request;

/* creates new request
   message can be freed after the call */
Request requestNew(char * message, size_t length);

void requestFree(Request req);

httpMethod requestMethod(Request req);

char *requestHost(Request req);

int requestPort(Request req);

char *requestUri(Request req);

Header requestHeader(Request req, char *fieldname);

void requestAddHeader(Request req, char *fieldname, char *fieldval);

int requestToString(Request req, char **strp);

#endif /* REQUEST_PARSER_DYNAMIC */
