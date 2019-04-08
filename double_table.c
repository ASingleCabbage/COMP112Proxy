#include "double_table.h"
#include <table.h>
#include <sys/time.h>

struct dtable{
    Table_T way1;
    Table_T way2;
};

/*optimized to store integers only*/
/*storing 0 may cause issues?*/

static int cmpInt(const uintptr_t a, const uintptr_t b){
    return (a < b) ? -1 : (a > b);
}

static unsigned hashWrap(const uintptr_t val){
    // Knuth's multiplicative method:
    return val*2654435761 % 2^32;

    // return hashlittle(key, 32, time(NULL));
}

DTable DTable_new(int hint){
    DTable dt = malloc(sizeof(struct dtable));

    dt->way1 = Table_new(hint, (int (*)(const void *, const void *))cmpInt, (unsigned int (*)(const void *))hashWrap);
    dt->way2 = Table_new(hint, (int (*)(const void *, const void *))cmpInt, (unsigned int (*)(const void *))hashWrap);
    return dt;
}

void DTable_free(DTable dt){
    Table_free(&(dt->way1));
    Table_free(&(dt->way2));
    free(dt);
}

void DTable_put(DTable dt, uintptr_t key, uintptr_t value){
    void *v1 = Table_put(dt->way1, (void *)key, (void *)value);
    if(v1 != NULL){
        Table_remove(dt->way1, v1);
    }
    void *v2 = Table_put(dt->way2, (void *)value, (void *)key);
    if(v2 != NULL){
        Table_remove(dt->way2, v2);
    }
}

int DTable_get(DTable dt, uintptr_t key){
    void * val = Table_get(dt->way1, (void *)key);
    if(val == NULL){
        val = Table_get(dt->way2, (void *)key);
    }
    return (uintptr_t)val;
}

void DTable_remove(DTable dt, uintptr_t key){
    void *val = Table_remove(dt->way1, (void *)key);
    if(val == NULL){
        val = Table_remove(dt->way2, (void *)key);
        Table_remove(dt->way1, (void *)val);
    }else{
        Table_remove(dt->way2, (void *)val);
    }
}
