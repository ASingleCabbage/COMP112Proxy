#ifndef INSPECTOR
#define INSPECTOR

#include "response_parser_dynamic.h"

void initInspector();

typedef enum { BLACKLIST, OWO } inspectorOptions;

void inspectToggleOptions(inspectorOptions options, char *value);

void inspectResponse(Response rsp);

#endif /* INSPECTOR */
