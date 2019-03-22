#ifndef REQUEST_PARSER
#define REQUEST_PARSER

#include <stdbool.h>
#include <stdlib.h>

//seperate type for response
typedef struct request *Request;

// NOTICE max stale has optional value that goes with it
// todo maybe split up response and request headers
// typedef enum {MAX_AGE, MAX_STALE, MIN_FRESH, N_CACHE, N_STORE, N_TRANSFORM,
//               ONLY_IF_CACHED, MUST_REVAL, PUBLIC, PRIVATE, PROXY_REVAL,
//               S_MAX_AGE} headerEntry;
typedef enum {MAX_AGE, MAX_STALE, MIN_FRESH, N_CACHE, N_STORE, N_TRANSFORM,
              ONLY_IF_CACHED } reqHeader;

// only contains method needed to be supported in the assignment
typedef enum {GET, CONNECT, OTHER} httpMethod;

/* creates new request
   message can be freed after the call */
Request requestNew(char * message, size_t length);

void requestFree(Request req);

/* sets pointer passed by reference to request uri, and returns length
   uri should be read only as no new memory is allocated */
int requestUri(Request req, char **urip);

/* sets pointer passed by reference to request host, and returns length
   host should be read only as no new memory is allocated
   returns -1 and sets hostp to NULL if host doesn'x exist */
int requestHost(Request req, char **hostp);

/* sets pointer passed by reference to request body, and returns length
   body should be read only as no new memory is allocated */
// removing as we are not caching requests
// size_t requestBody(Request req, char **bodyp);

/* returns true if a cache control header exists in request */
bool requestHasHeader(Request req, reqHeader hdr);

/* returns value of a given header entry
  -1 if entry not in header or has no value (e.g. cache-control : no-cache)*/
int requestHeaderValue(Request req, reqHeader hdr);

/* Seperate getter and setter for age as it's the only field we can update */
// removing this as we are only caching responses not requests
// int requestGetAge(Request req, int age);
// void requestSetAge(Request req, int age);

/* sets pointer passed by reference to the entire request, and returns length
   allocates memory, char **s has to be freed afterwards */
// removing as we are not caching requests
// size_t requestToString(Request req, char **s);

#endif /* REQUEST_PARSER */
