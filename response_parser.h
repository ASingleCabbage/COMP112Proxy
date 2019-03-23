#ifndef RESPONSE_PARSER
#define RESPONSE_PARSER

#include <stdbool.h>

//seperate type for response
typedef struct response *Response;

typedef enum {RSP_MAX_AGE, RSP_S_MAX_AGE, RSP_MUST_REVAL, RSP_N_CACHE, RSP_N_STORE, RSP_N_TRANSFORM,
              RSP_PUBLIC, RSP_PRIVATE, RSP_PROXY_REVAL} rspHeader;

Response responseNew(char * message, size_t length);

void responseFree(Response rsp);

int responseStatus(Response rsp);

bool responseHasHeader(Response rsp, rspHeader hdr);

int responseHeaderValue(Response rsp, rspHeader hdr);

int responseGetAge(Response rsp, int age);
void responseSetAge(Response rsp, int age);

size_t responseToString(Response rsp, char **s);

#endif /* RESPONSE_PARSER */
