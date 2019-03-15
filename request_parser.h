#ifndef REQUEST_PARSER
#define REQUEST_PARSER

typedef struct reqest *Request;

Request request_new(char * message, size_t length);

#endif /* REQUEST_PARSER */
