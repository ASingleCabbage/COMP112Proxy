#include "http_header.h"
#include <string.h>
#include <stdlib.h>
#define BUF_SIZE 128

Header getHeader(Header head, char *fieldname){
    while(head != NULL){
        if(strcmp(fieldname, head->name) == 0){
            return head;
        }
        head = head->next;
    }
    return NULL;
}

/* Replaces existing if exists */
void addHeader(Header *headp, char *name, char *value){
    Header header = getHeader(*headp, name);
    if(header == NULL){
        Header header = malloc(sizeof(struct Header));
        header->name = name;
        header->value = value;
        header->next = *headp;
        *headp = header;
    }else{
        free(header->name);
        free(header->value);
        header->name = name;
        header->value = value;
    }
}

void removeHeader(Header *headp, char *name){
    if(*headp == NULL){
        return;
    }

    Header curr = *headp;
    if(strcmp(curr->name, name) == 0){
        *headp = curr->next;
        free(curr->name);
        free(curr->value);
        free(curr);
        return;
    }

    Header prev = curr;
    curr = curr->next;
    while(curr != NULL){
        if(strcmp(curr->name, name) == 0){
            prev->next = curr->next;
            free(curr->name);
            free(curr->value);
            free(curr);
            return;
        }
    }
    return;
}

/* Appends values if field already exists, else create a new header entry */
void appendHeader(Header *headp, char *name, char *value){
    Header header = getHeader(*headp, name);
    if(header == NULL){
        /* Identical with addHeader */
        Header header = malloc(sizeof(struct Header));
        header->name = name;
        header->value = value;
        header->next = *headp;
        *headp = header;
    }else{
        /* adding 1 for null terminator, and 1 for ; seperator*/
        int len1 = strlen(header->value);
        int len2 = strlen(value);
        int newLen = len1 + len2 + 2;
        header->value = realloc(header->value, newLen);
        (header->value)[len1] = ',';
        memcpy(header->value + len1 + 1, value, len2);
        (header->value)[newLen] = '\0';
    }
}

void freeHeader(Header head){
    Header tmp;
    while(head != NULL){
        tmp = head->next;
        free(head->name);
        free(head->value);
        free(head);
        head = tmp;
    }
}

int toStringHeader(Header h, char **strp){
    int length = 0;
    int capacity = BUF_SIZE;
    int newLength, nlen, vlen;

    *strp = malloc(capacity);
    while(h != NULL){
        newLength = length;
        nlen = strlen(h->name);
        vlen = strlen(h->value);
        newLength += 4; /* seperator between name and value, and \r\n at the end */
        newLength += nlen; /* seperator between name and value */
        newLength += vlen; /* seperator between name and value */

        while(newLength > capacity){
            capacity += BUF_SIZE;
            *strp = realloc(*strp, capacity + 1);
        }
        memcpy((*strp) + length, h->name, nlen);
        (*strp)[length + nlen] = ':';
        (*strp)[length + nlen + 1] = ' ';
        memcpy((*strp) + length + nlen + 2, h->value, vlen);
        (*strp)[newLength - 2] = '\r';
        (*strp)[newLength - 1] = '\n';
        length = newLength;
        h = h->next;
    }
    (*strp)[length] = '\0';
    return length;
}

bool headerHasValue(Header h, char *target, char *delim){
    char *vals = strdup(h->value);

    char *token = strsep(&vals, delim); /*whitespace may need stripping, not sure*/
    while(vals != NULL){
        if(strlen(token) < 1){
            break;
        }
        if(strcmp(token, target) == 0){
            return true;
        }
        token = strsep(&vals, ",");
    }
}
