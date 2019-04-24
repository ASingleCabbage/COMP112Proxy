#ifndef RESPONSE_PARSER
#define RESPONSE_PARSER

#include <stdbool.h>
#include <stdlib.h>

//seperate type for response
typedef struct response *Response;

//SSL support
typedef struct sResponse *SResponse;
SResponse responseNewS(char *message, size_t length);
void responseFreeS(SResponse srsp);

typedef enum {RSP_MAX_AGE, RSP_S_MAX_AGE, RSP_MUST_REVAL, RSP_N_CACHE, RSP_N_STORE, RSP_N_TRANSFORM,
              RSP_PUBLIC, RSP_PRIVATE, RSP_PROXY_REVAL, RSP_CONTENT_LEN} rspHeader;

/* message can be freed after the call */
Response responseNew(char * message, size_t length);

void responseFree(Response rsp);

int responseStatus(Response rsp);

bool responseHasHeader(Response rsp, rspHeader hdr);

int responseHeaderValue(Response rsp, rspHeader hdr);

/* Response itself contains age field, so can be directly cached in a data structure */
int responseGetAge(Response rsp);
void responseSetAge(Response rsp, int age);

size_t responseToCharAry(Response rsp, char **msgp);

#endif /* RESPONSE_PARSER */
