#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "response_parser_dynamic.h"

int main(void) {
    char *raw_request = "HTTP/1.1 200 OK\r\n"
            "Host: localhost:8080\r\n"
            "Connection: keep-alive\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6\r\n"
            "Accept-Language: en-us\r\n"
            "DNT: 1\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "\r\n"
            "Usually GET requests don\'t have a body\r\n"
            "But I don\'t care in this case :)";
            fprintf(stderr, "Parsing...\n", );
    Response req = responseNew(raw_request, strlen(raw_request));
    fprintf(stderr, "Parsing complete\n");
    char *str;
    responseToString(req, &str);
    fprintf(stderr, "TO STRING\n%s\n", str);


    // if (req) {
    //     printf("Method: %d\n", req->method);
    //     printf("Request-URI: %s\n", req->url);
    //     printf("HTTP-Version: %s\n", req->version);
    //     puts("Headers:");
    //     struct Header *h;
    //     for (h=req->headers; h; h=h->next) {
    //         printf("%32s: %s\n", h->name, h->value);
    //     }
    //     puts("message-body:");
    //     puts(req->body);
    // }
    responseFree(req);
    return 0;
}
