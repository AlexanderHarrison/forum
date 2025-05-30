#include "../vendor/mongoose.h"
#include "../vendor/sqlite3.h"

#include <stdbool.h>
#include <stdio.h>

sqlite3 *db;
sqlite3_stmt *insert_stmt;
sqlite3_stmt *read_stmt;

#define expect(A) do {\
    if (!(A)) {\
        fprintf(stderr, "expect failed - " __FILE__ ":%u: '" #A "'\n", __LINE__);\
        exit(1);\
    }\
} while (0)

void mg_print_str(const char *preface, struct mg_str str) {
    printf("%s%.*s\n", preface, (int) str.len, str.buf);
}

void mg_serve_str(struct mg_connection *c, struct mg_str str) {
    const char *headers = "Content-Type: text/html; charset=utf-8\r\n";
    mg_http_reply(c, 200, headers, "%.*s", (int)str.len, str.buf);
}

void mg_all_good(struct mg_connection *c) {
    mg_http_reply(c, 200, NULL, "");
}

void mg_bad_request(struct mg_connection *c) {
    mg_http_reply(c, 400, NULL, "");
}

void insert_row(struct mg_str str) {
    mg_print_str("INSERT: ", str);
    
    expect(sqlite3_bind_text(insert_stmt, 1, str.buf, (int)str.len, NULL) == SQLITE_OK);
    expect(sqlite3_step(insert_stmt) == SQLITE_DONE);
    expect(sqlite3_reset(insert_stmt) == SQLITE_OK);
}

struct mg_str mg_find_key(struct mg_str body, const char *key) {
    size_t keylen = strlen(key);
    
    for (size_t i = 0; i + keylen < body.len; ++i) {
        if (strncmp(body.buf + i, key, keylen) == 0) {
            if (body.buf[i+keylen] == '=') {
                size_t start = i + keylen + 1;
                size_t end = start;
                
                while (end < body.len) {
                    if (body.buf[end] == '&') break;
                    end++;
                }
                
                return (struct mg_str) { .buf = body.buf + start, .len = end - start };
            }
        }
    }
    
    return (struct mg_str) { 0 };
}

// returned str must be freed
struct mg_str read_rows(void) {
    size_t bufsize = 4096;
    
    char *buf = malloc(bufsize);
    size_t head = 0;
    
    while (1) {
        int ret = sqlite3_step(read_stmt);
        if (ret == SQLITE_DONE) break;
        expect(ret == SQLITE_ROW);
        
        const unsigned char *text = sqlite3_column_text(read_stmt, 0);
        
        while (1) {
            size_t left = bufsize - head;
            size_t written = (size_t)snprintf(buf + head, left, "%s\n\n", text);
            expect(written > 0);
            
            if (written < left) {
                head += written;
                break;
            } else {
                // output truncated - realloc and try again
                bufsize *= 2;
                buf = realloc(buf, bufsize);
            }
        }
    }
    
    expect(sqlite3_reset(read_stmt) == SQLITE_OK);
    
    return (struct mg_str) { .buf = buf, .len = head };
}

void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        mg_print_str("URI: ", hm->uri);
        
        struct mg_http_serve_opts opts = { .root_dir = "./web_root/" };
        if (mg_match(hm->uri, mg_str("/test"), NULL)) {
            mg_serve_str(c, mg_str("mg text!"));
        }
        else if (mg_match(hm->uri, mg_str("/insert"), NULL)) {
            struct mg_str val = mg_find_key(hm->body, "text");
            
            if (val.buf != NULL) {
                insert_row(val);
                mg_all_good(c);
            } else {
                mg_bad_request(c);
            }
        }
        else if (mg_match(hm->uri, mg_str("/read"), NULL)) {
            struct mg_str items = read_rows();
            mg_serve_str(c, items);
            free(items.buf);
        }
        else {
            mg_http_serve_dir(c, hm, &opts);
        }
    }
}

int main(void) {
    // INIT DB ------------------------------------------
    
    expect(sqlite3_open_v2("db.sqlite", &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
    
    const char sql_insert[] = "INSERT INTO rows VALUES ( ? );";
    const char sql_read[]   = "SELECT text FROM rows;";
    
    expect(sqlite3_prepare_v2(db, sql_insert, sizeof(sql_insert), &insert_stmt, NULL) == SQLITE_OK);
    expect(sqlite3_prepare_v2(db, sql_read, sizeof(sql_read), &read_stmt, NULL) == SQLITE_OK);
    
    // RUN SERVER ------------------------------------------

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:10000", ev_handler, NULL);
    while (true) {
        mg_mgr_poll(&mgr, -1);
    }
    return 0;
}
