#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "response_parser.h"
#include "request_parser.h"

size_t readFile(char **ptr, char *filename){
    /* declare a file pointer */
    FILE    *infile;
    char    *buffer;
    long    numbytes;

    /* open an existing file for reading */
    infile = fopen(filename, "r");

    /* quit if the file does not exist */
    if(infile == NULL)
        return 1;

    /* Get the number of bytes */
    fseek(infile, 0L, SEEK_END);
    numbytes = ftell(infile);

    /* reset the file position indicator to
    the beginning of the file */
    fseek(infile, 0L, SEEK_SET);

    /* grab sufficient memory for the
    buffer to hold the text */
    buffer = (char*)calloc(numbytes, sizeof(char));

    /* memory error */
    if(buffer == NULL)
        return 1;

    /* copy all the text into the buffer */
    fread(buffer, sizeof(char), numbytes, infile);
    fclose(infile);
    *ptr = buffer;
    return numbytes;
}

int main(){
    FILE * fp;
    char * line = NULL;
    size_t read;

    fp = fopen("request_log.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    // size_t len = 0;
    // while ((read = getdelim(&line, &len, '~', fp)) != -1) {
    //     line[read - 17] = '\0';
    //     read -= 16;
    //     printf("%s %d\n", line, read);

        // request testing code
        // Request req = requestNew(line, read);
        // if(req == NULL){
        //     continue;
        // }
        // char *uri;
        // requestUri(req, &uri);
        // char *meth;
        // switch(requestMethod(req)){
        //     case GET:
        //         meth = "GET";
        //         break;
        //     case CONNECT:
        //         meth = "CONNECT";
        //         break;
        //     case OTHER:
        //         meth = "OTHER";
        //         break;
        // }
        // printf("Uri: %s | Method: %s\n", uri, meth);
    // }
    //
    // fclose(fp);


    read = readFile(&line, "response_log.txt");
    fprintf(stderr, "File read, %lu bytes\n", read);
    fprintf(stderr, "%s\n", line);

    Response rsp = responseNew(line, read);
    if(rsp != NULL){
        printf("Status: %d | Age: %d\n", responseStatus(rsp), responseGetAge(rsp));
        responseSetAge(rsp, 5);
        printf("Status: %d | Age: %d\n", responseStatus(rsp), responseGetAge(rsp));
        char *out;
        size_t outLen = responseToCharAry(rsp, &out);
        printf("Response (reported size %lu, strlen %lu):\n%s\n", outLen, strlen(out), out);
        printf("Response field max age : %d\n", responseHeaderValue(rsp, RSP_MAX_AGE));

        responseFree(rsp);
    }else{
        fprintf(stderr, "Error: response not created");
    }
    if (line)
        free(line);
    return EXIT_SUCCESS;
}
