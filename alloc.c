/*
 * Copyright (c) 2020, Michael Grunder <michael dot grunder at gmail dot com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "alloc.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static hiredisAllocFuncs s_hiredisAllocFns = {
    malloc,
    calloc,
    realloc,
    strdup,
    free,
};

#ifdef __cplusplus
extern "C" {
#endif

/* Override hiredis' allocators with ones supplied by the user */
hiredisAllocFuncs hiredisSetAllocators(hiredisAllocFuncs *ha) {
    hiredisAllocFuncs orig = s_hiredisAllocFns;

    s_hiredisAllocFns = *ha;

    return orig;
}

/* Reset allocators to use libc defaults */
void hiredisResetAllocators(void) {
    s_hiredisAllocFns.mallocFn = malloc;
    s_hiredisAllocFns.callocFn = calloc;
    s_hiredisAllocFns.reallocFn = realloc;
    s_hiredisAllocFns.strdupFn = strdup;
    s_hiredisAllocFns.freeFn = free;
}

void *hi_malloc(size_t size) {
    return s_hiredisAllocFns.mallocFn(size);
}

void *hi_calloc(size_t nmemb, size_t size) {
    /* Overflow check as the user can specify any arbitrary allocator */
    if (SIZE_MAX / size < nmemb)
        return NULL;

    return s_hiredisAllocFns.callocFn(nmemb, size);
}

void *hi_realloc(void *ptr, size_t size) {
    return s_hiredisAllocFns.reallocFn(ptr, size);
}

char *hi_strdup(const char *str) {
    return s_hiredisAllocFns.strdupFn(str);
}

void hi_free(void *ptr) {
    s_hiredisAllocFns.freeFn(ptr);
}

#ifdef __cplusplus
}
#endif
