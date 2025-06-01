// UTILS --------------------------------------

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <math.h>

typedef uint64_t U64;
typedef uint32_t U32;
typedef uint16_t U16;
typedef uint8_t  U8;
typedef int64_t I64;
typedef int32_t I32;
typedef int16_t I16;
typedef int8_t  I8;
typedef size_t Usize;

typedef struct Arena {
    U8 *base;
    U8 *head;
    U64 size;
} Arena;

typedef struct {
    U8 *head;
} ArenaResetPoint;

typedef struct mg_str Str;
#define NULL_STR ((Str) {0})

#ifndef PROD
    #define expect(A) do {\
        if (!(A)) {\
        fprintf(stderr, "expect failed - " __FILE__ ":%u: '" #A "'\n", __LINE__);\
        exit(1);\
    }\
    } while (0)
#else
    #define expect(A)
#endif

#define sql_ok(A) expect((A) == SQLITE_OK)
#define sql_done(A) expect((A) == SQLITE_DONE)

#define ALIGN_UP(p, align) (void*)(((Usize)(p) + ((Usize)align) - 1) & ~(((Usize)align) - 1))

// VIRTUAL MEMORY --------------------------

static _Thread_local Usize page_size_global = 0;
Usize page_size(void) {
    if (page_size_global == 0) {
        page_size_global = (Usize)sysconf(_SC_PAGESIZE);
    }
    return page_size_global;
}

// always zero initialized
void *vm_alloc(Usize size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

int vm_dealloc(void *ptr, Usize size) {
    return munmap(ptr, size);
}

// ARENA -----------------------------------

Arena arena_create(U64 size) {
    void *base = vm_alloc(size);
    expect(base != MAP_FAILED);
    return (Arena) {
        .base = base,
        .head = base,
        .size = size,
    };
}

void *arena_alloc(Arena *b, Usize size, Usize align) {
    U8 *head = b->head;
    U8 *aligned = ALIGN_UP(head, align);
    b->head = aligned + size;
    expect((U64)(b->head - b->base) < b->size);
    return aligned;
}

void *arena_prealign(Arena *b, Usize align) {
    return arena_alloc(b, 0, align);
}

void arena_clear(Arena *b) {
    b->head = b->base;
}

ArenaResetPoint arena_reset_point(Arena *arena) {
    return (ArenaResetPoint) { arena->head };
}

void arena_reset(Arena *arena, ArenaResetPoint *reset_point) {
    #ifndef PROD
        expect(arena->base <= reset_point->head);
        expect(arena->base + arena->size > reset_point->head);
        memset(reset_point->head, 0, (size_t)(arena->head - reset_point->head));
    #endif

    arena->head = reset_point->head;
}

void arena_destroy(Arena *b) {
    expect(vm_dealloc(b->base, b->size) == 0);
}

Str arena_strdup_t(Arena *b, const char *s) {
    if (s == NULL) return NULL_STR;
    size_t len = strlen(s);
    char *buf = arena_alloc(b, len, 1);
    memcpy(buf, s, len);
    return (Str) { buf, len };
}

// STRING CONSTRUCTION -----------------------------------

Str str_create(char *str) {
    if (str == NULL)
        return NULL_STR;
    return (Str) { str, strlen(str) };
}

bool str_null(Str str) { return str.buf == NULL; }

typedef struct StrCons {
    Arena *arena;
    U8 *str;
} StrCons;

StrCons strcons_create(Arena *arena) {
    return (StrCons) { arena, arena->head };
}

void strcons_append(StrCons *strcons, Str str) {
    U8 *target = arena_alloc(strcons->arena, str.len, 1);
    memcpy(target, str.buf, str.len);
}

void strcons_append_t(StrCons *strcons, const char *str) {
    Usize len = strlen(str);
    U8 *target = arena_alloc(strcons->arena, len, 1);
    memcpy(target, str, len);
}

// return constructed string
Str strcons_str(StrCons *strcons) {
    size_t len = (size_t)(strcons->arena->head - strcons->str);
    return (Str) { (char*)strcons->str, len };
}

// null terminate and return constructed string
char *strcons_str_t(StrCons *strcons) {
    *(U8*)arena_alloc(strcons->arena, 1, 1) = '\0';
    return (char*)strcons->str;
}

