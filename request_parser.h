#ifndef REQUEST_PARSER
#define REQUEST_PARSER

#include <stdbool.h>
#include <stdlib.h>

//seperate type for response
typedef struct request *Request;

// NOTICE max stale has optional value that goes with it
typedef enum {REQ_MAX_AGE, REQ_MAX_STALE, REQ_MIN_FRESH, REQ_N_CACHE, REQ_N_STORE, REQ_N_TRANSFORM,
              REQ_ONLY_IF_CACHED, REQ_CONTENT_LEN } reqHeader;

// only contains method needed to be supported in the assignment
typedef enum {GET, CONNECT, OTHER} httpMethod;

/* creates new request
   message can be freed after the call */
Request requestNew(char * message, size_t length);

void requestFree(Request req);

httpMethod requestMethod(Request req);

/* sets pointer passed by reference to request uri, and returns length
   uri should be read only as no new memory is allocated */
size_t requestUri(Request req, char **urip);

/* sets pointer passed by reference to request host, and returns length
   host should be read only as no new memory is allocated
   returns -1 and sets hostp to NULL if host doesn't exist */
size_t requestHost(Request req, char **hostp);

int requestPort(Request req);

/* returns true if a cache control header exists in request */
bool requestHasHeader(Request req, reqHeader hdr);

/* returns value of a given header entry
  -1 if entry not in header or has no value (e.g. cache-control : no-cache)*/
int requestHeaderValue(Request req, reqHeader hdr);

/* read only */
int requestToCharAry(Request req, char **msgp);

#endif /* REQUEST_PARSER */
