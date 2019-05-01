#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "inspector.h"
#include <zlib.h>

static void censorHtml(char *html, int len){
    fprintf(stderr, "[INSPECTOR] Redacting blacklisted terms\n");
    char *start = NULL;
    bool styleZone = false;
    bool scriptZone = false;
    for(int i = 0; i < len; i++){
        if(html[i] == '<'){
            /* assumes no nested tag strings */
            if(styleZone && strncmp(html + i, "/H2", 3) == 0){
                i += 3;
                styleZone = false;
            }else if(scriptZone && strncmp(html + i, "/P", 2) == 0){
                i += 2;
                scriptZone = false;
            }else if(strncmp(html + i, "P", 1) == 0){
                i += 1;
                scriptZone = true;
            }else if(strncmp(html + i, "H2", 2) == 0){
                i += 2;
                styleZone = true;
            }else if(start != NULL){
                *(html + i) = '\0';
                fprintf(stderr, "ROI: %s\n", start);
            }
        }else if(html[i] == '>'){
            if(!styleZone && !scriptZone){
                start = html + i;
            }
        }
    }
}

int main(void) {
    char *html = strdup("<HTML>\n<HEAD>\n\n<TITLE>Your Title Here</TITLE>\n</HEAD>\n"
             "<BODY BGCOLOR=\"FFFFFF\">\n<CENTER><IMG SRC=\"clouds.jpg\" ALIGN=\"BOTTOM\">"
             "</CENTER>\n<HR>\n<a href=\"http://somegreatsite.com\">Link Name</a>\n"
             "is a link to another nifty site\n<H1>This is a Header</H1>\n"
             "<H2>This is a Medium Header</H2>\nSend me mail at <a href=\"mailto:support@yourcompany.com\">"
             "\nsupport@yourcompany.com</a>.\n<P> This is a new paragraph!\n</P>"
             "<B>This is a new paragraph!</B>\n<BR> <B><I>This is a new sentence without "
             "a paragraph break, in bold italics.</I></B>\n<HR>\n</BODY>\n</HTML>");
    
    fprintf(stderr, "BEFORE:\n%s\n", html);

    // initInspector();
    censorHtml(html, strlen(html));
    
    fprintf(stderr, "AFTER:\n%s\n", html);

    
    
    return 0;
}
