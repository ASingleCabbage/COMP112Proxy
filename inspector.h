#ifndef INSPECTOR
#define INSPECTOR

#include "response_parser_dynamic.h"

void initInspector();

// void censorRegion(char *start, char *end);
// void censorHtml(char *html, int len);

void inspectResponse(Response rsp);

#endif /* INSPECTOR */
