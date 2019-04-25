#ifndef RESPONSE_PARSER_DYNAMIC
#define RESPONSE_PARSER_DYNAMIC

#include <stdbool.h>
#include <stdlib.h>
#include "http_header.h"

//seperate type for response
typedef struct response *Response;

/* creates new response
   message can be freed after the call */
Response responseNew(char * message, size_t length);

void responseFree(Response rsp);

/* reason phrase is read only */
int responseStatus(Response rsp, char **reasonp);

Header responseHeader(Response rsp, char *fieldname);

void responseAddHeader(Response rsp, char *fieldname, char *fieldval);

int responseToString(Response rsp, char **strp);

#endif /* RESPONSE_PARSER_DYNAMIC */
