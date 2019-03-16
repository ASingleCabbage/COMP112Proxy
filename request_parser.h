#ifndef REQUEST_PARSER
#define REQUEST_PARSER

#include <stdbool.h>
#include <stdlib.h>

typedef struct reqest *Request;
typedef enum {MAX_AGE, MAX_STALE, MIN_FRESH, N_CACHE, N_STORE, N_TRANSFORM,
              ONLY_IF_CACHED, MUST_REVAL, PUBLIC, PRIVATE, PROXY_REVAL,
              S_MAX_AGE, CACHE_AGE} headerEntry;

/* creates new request
   message can be freed after the call */
Request requestNew(char * message, size_t length);

void requestFree(Request req);

/* sets pointer passed by reference to request body, and returns length
   body is immutable as no new memory is allocated */
size_t requestBody(Request req, char **);

/* returns value of a given header entry
  -1 if entry not in header
  0 if entry in header but doesn't have value (e.g. cache-control : no-cache)*/
int requestHeaderValue(Request req, headerEntry entry);

/* Seperate setter for age as it's the only field we can update */
void requestSetAge(Request req, int age);

/* sets pointer passed by reference to the entire request, and returns length
   allocates memory, char **s has to be freed afterwards */
size_t requestToString(Request req, char **s);

#endif /* REQUEST_PARSER */
