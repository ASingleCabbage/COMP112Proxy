#define _GNU_SOURCE
#include "inspector.h"
#include "http_header.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "libdeflate.h"

#define ASCII_BLOCK_CHAR 219
#define WORDLIST_LEN_HINT 10

#define COMPRESS_LEVEL 4 /* 1-12, higher slower */
#define INITIAL_DECOMPRESS_FACTOR 4

char *inspector_blacklist_word;
static struct libdeflate_compressor *Compressor;
static struct libdeflate_decompressor *Decompressor;

static bool inspector_option_owo;
static bool inspector_option_blacklist;

void initInspector(){
    Compressor = libdeflate_alloc_compressor(COMPRESS_LEVEL);
    Decompressor = libdeflate_alloc_decompressor();

    inspector_option_owo = true;
    inspector_option_blacklist = true;

    inspector_blacklist_word = strdup("network");
    fprintf(stderr, "[INSPECTOR] Initialized\n");
}

static void stripRearSpace(char *str, int len){
    int index;
    if(len < 0){
        index = strlen(str) - 1;
    }else{
        index = len - 1;
    }
    while(index >= 0){
        if(isspace(str[index])){
            str[index] = '\0';
        }else{
            return;
        }
        index--;
    }
}

/* Retries by doubling initial buffer size if insufficient buffer size */
static int gzipDecompress(char *data, int len, char **decompressp){
    int decompressFactor = INITIAL_DECOMPRESS_FACTOR;
    size_t bufSize = len * decompressFactor; /* assuming a compression factor of 2 */
    *decompressp = malloc(bufSize);
    
    size_t resultSize;
    int result = libdeflate_gzip_decompress(Decompressor, data, len, *decompressp, bufSize, &resultSize);
    
    while(result == LIBDEFLATE_INSUFFICIENT_SPACE){
        decompressFactor *= 2;
        bufSize = len * decompressFactor;
        *decompressp = realloc(*decompressp, bufSize);
        fprintf(stderr, "[INSPECTOR] GZIP DECOMRESS FAIL: Insufficient buffer size; retrying with factor %d\n", decompressFactor);
        result = libdeflate_gzip_decompress(Decompressor, data, len, *decompressp, bufSize, &resultSize);
    }

    switch (result)
    {
        case LIBDEFLATE_SUCCESS:
            fprintf(stderr, "[INSPECTOR] Decompression complete, %d ===> %lu bytes\n", len, resultSize);
            return resultSize;
        case LIBDEFLATE_INSUFFICIENT_SPACE:
            fprintf(stderr, "GZIP DECOMRESS FAIL Out of memory\n");
            return -1;
        case LIBDEFLATE_BAD_DATA:
            fprintf(stderr, "GZIP DATA ERROR\n");
            return -1;
        default:
            fprintf(stderr, "GZIP DECOMPRESS UNEXPECTED CASE %d\n", result);
            return -1;
    }
}

/* Unlike decompress, we give up if fail on first try */
static int gzipCompress(char *data, int len, char **compressp){
    /* gzip requires 1.01x + 12 bytes; allocating more just to be safe */
    int bufSize = len * 1.1 + 12; 
    *compressp = malloc(bufSize);
    int result = libdeflate_gzip_compress(Compressor, data, len, *compressp, bufSize);
    return result;
}

void inspectToggleOptions(inspectorOptions options, char *value){
    switch (options)
    {
        case OWO:
            inspector_option_owo = !inspector_option_owo;
            fprintf(stderr, "[INSPECTOR] Set option OwO to %d\n", inspector_option_owo);
             fprintf(stderr,"                 *Notices Proxy*\n"
                   " __        ___           _    _        _   _     _      \n"
                    "\\ \\      / / |__   __ _| |_ ( ) ___  | |_| |__ (_) ___ \n"
                   " \\ \\ /\\ / /| '_ \\ / _\\`| __|// / __| | __| '_ \\| |/ __|\n"
                   "  \\ V  V / | | | | (_| | |_    \\__ \\ | |_| | | | |\\__ \\\n"
                   "   \\_/\\_/  |_| |_|\\__,_|\\__|   |___/ \\___|_| |_|_|/___/\n");
            break;
        case BLACKLIST:
            if(value == NULL){
                inspector_option_blacklist = !inspector_option_blacklist;
                fprintf(stderr, "[INSPECTOR] Set option blacklist to %d\n", inspector_option_blacklist);
            }else{
                free(inspector_blacklist_word);
                stripRearSpace(value, -1);
                inspector_blacklist_word = strdup(value);
                fprintf(stderr, "[INSPECTOR] Updated blacklist phrase to [%s]\n", inspector_blacklist_word);
            }
            break;
    }


}

static void censorRegion(char *start, char *end){
    char *target = inspector_blacklist_word;
    int targetLen = strlen(target);
    *end = '\0';

    char *ret = strcasestr(start, target);
    while(ret != NULL){
        // fprintf(stderr, "String found %s --> ", ret);
        memset(ret, ASCII_BLOCK_CHAR, targetLen);
        // fprintf(stderr, "%s\n", ret);
        ret = strcasestr(ret + targetLen, target);
    }
    *end = '<';
}

static void OwO(char *start, char *end){
    *end = '\0';
    int i = 0;
    while(true){
        switch (start[i]){
            case 'r':
            case 'l':
                start[i] = 'w';
                break;
            case 'R':
            case 'L':
                start[i] = 'W';
                break;
            case '\0':
                start[i] = '<';
                return;
        }
        i++;
    }
}

static void censorHtml(char *html, int len){
    fprintf(stderr, "[INSPECTOR] Redacting blacklisted terms\n");
    bool styleZone = false;
    bool scriptZone = false;
    char *start = NULL;
    for(int i = 0; i < len; i++){
        if(html[i] == '<'){
            /* assumes no nested tag strings */
            if(styleZone && strncmp(html + i, "/style", 6) == 0){
                i += 6;
                styleZone = false;
            }else if(scriptZone && strncmp(html + i, "/script", 7) == 0){
                i += 7;
                scriptZone = false;
            }else if(strncmp(html + i, "script", 6) == 0){
                i += 6;
                scriptZone = true;
            }else if(strncmp(html + i, "style", 5) == 0){
                i += 5;
                styleZone = true;
            }else if(start != NULL){
                if(inspector_option_blacklist){
                    censorRegion(start, html + i);
                }
                if(inspector_option_owo){
                    OwO(start, html + i);
                }
            }
        }else if(html[i] == '>'){
            if(!styleZone && !scriptZone){
                start = html + i;
            }
        }
    }
}

/* Handles all store forward traffic; should've increased modularity but this will do */
void inspectResponse(Response rsp){
    Header contentType = responseHeader(rsp, "Content-Type");
    if(headerHasValue(contentType, "text/html", ";")){
        char *content;
        int contentLen = responseBody(rsp, &content);
        Header encoding = responseHeader(rsp, "Content-Encoding");
        if(encoding == NULL){
            censorHtml(content, contentLen);
        }else if(headerHasValue(encoding, "gzip", ",")){
            fprintf(stderr, "[INSPECTOR] Gzip content encoding; decoding first...\n");
            char *dstr;
            int dlen = gzipDecompress(content, contentLen, &dstr);
            if(dlen == -1){
                free(dstr);
                return;
            }           
            censorHtml(dstr, dlen);
            char *cstr;
            int clen = gzipCompress(dstr, dlen, &cstr);
            if(clen == -1){
                free(dstr);
                free(cstr);
                return;
            }

            responseUpdateBody(rsp, cstr, clen);

            free(dstr);
            free(cstr);
            return;
        }else{
            fprintf(stderr, "[INSPECTOR] No supported encoding format\n");
        }
    }
}
