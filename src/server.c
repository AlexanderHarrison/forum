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

void insert_row(const char *username, const char *message) {
    printf("%s - %s\n", username, message);
    
    int username_len = (int)strlen(username);
    int message_len = (int)strlen(message);
    expect(sqlite3_bind_text(insert_stmt, 1, username, username_len, NULL) == SQLITE_OK);
    expect(sqlite3_bind_text(insert_stmt, 2, message, message_len, NULL) == SQLITE_OK);
    expect(sqlite3_step(insert_stmt) == SQLITE_DONE);
    expect(sqlite3_reset(insert_stmt) == SQLITE_OK);
}

// returned str must be freed
struct mg_str read_rows(void) {
    size_t bufsize = 4096;
    
    char *buf = malloc(bufsize);
    size_t head = 0;
    
    head = (size_t)snprintf(buf, bufsize, "<div id=chat>");
    
    while (1) {
        int ret = sqlite3_step(read_stmt);
        if (ret == SQLITE_DONE) break;
        expect(ret == SQLITE_ROW);
        
        const unsigned char *username = sqlite3_column_text(read_stmt, 0);
        const unsigned char *message = sqlite3_column_text(read_stmt, 1);
        
        while (1) {
            size_t left = bufsize - head;
            size_t written = (size_t)snprintf(buf + head, left, "%s: %s<br>", username, message);
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
    
    // TODO this can oob
    head += (size_t)snprintf(buf + head, bufsize - head, "</div>");
    
    expect(sqlite3_reset(read_stmt) == SQLITE_OK);
    
    return (struct mg_str) { .buf = buf, .len = head };
}

void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        mg_print_str("URI: ", hm->uri);
        
        if (mg_match(hm->uri, mg_str("/ws"), NULL)) {
            mg_ws_upgrade(c, hm, NULL);
            c->data[0] = 'W';
            
            struct mg_str items = read_rows();
            mg_ws_send(c, items.buf, items.len, WEBSOCKET_OP_TEXT);
        }
        else {
            struct mg_http_serve_opts opts = { .root_dir = "./web_root/" };
            mg_http_serve_dir(c, hm, &opts);
        }
    }
    else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
        mg_print_str("WS DATA: ", wm->data);
        
        char *todo = mg_json_get_str(wm->data, "$.HEADERS.HX-Target");
        expect(todo != NULL);
        
        if (strcmp(todo, "post-message") == 0) {
            char *username = mg_json_get_str(wm->data, "$.username");
            char *message = mg_json_get_str(wm->data, "$.message");
            expect(username != NULL);
            expect(message != NULL);
            insert_row(username, message);
            
            struct mg_str items = read_rows();
            printf("broadcasting...\n");
            for (struct mg_connection *wc = c->mgr->conns; wc != NULL; wc = wc->next) {
                if (wc->data[0] == 'W')
                    mg_ws_send(wc, items.buf, items.len, WEBSOCKET_OP_TEXT);
            }
            free(items.buf); 
        }
    }
}

int main(void) {
    // INIT DB --------------------------------------------
    
    expect(sqlite3_open_v2("db.sqlite", &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
    
    const char sql_insert[] = "INSERT INTO chatlog VALUES ( ?, ? );";
    const char sql_read[]   = "SELECT username, message FROM chatlog;";
    
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
