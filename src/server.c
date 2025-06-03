#include "../vendor/mongoose.h"
#include "../vendor/sqlite3.h"

#include "utils.c"

#include <stdbool.h>
#include <stdio.h>

sqlite3 *db;
sqlite3_stmt *stmt_post_message;
sqlite3_stmt *stmt_signup;
sqlite3_stmt *stmt_login;
sqlite3_stmt *stmt_read_history;
sqlite3_stmt *stmt_username_id;
sqlite3_stmt *stmt_email_id;
sqlite3_stmt *stmt_get_user;
sqlite3_stmt *stmt_add_session;
sqlite3_stmt *stmt_session_user;
sqlite3_stmt *stmt_end_session;

static const char sql_post_message[] = "INSERT INTO chatlog VALUES ( ?, ? );";
static const char sql_signup[] = "INSERT INTO users VALUES ( ?, ?, ?, ?, ? );";
static const char sql_login[] = "SELECT user_id FROM users WHERE ( login_hash = ? );";
static const char sql_read_history[] = "SELECT username, message FROM chatlog JOIN users WHERE chatlog.user_id = users.user_id;";
static const char sql_username_id[] = "SELECT user_id FROM users WHERE ( username = ? );";
static const char sql_email_id[] = "SELECT user_id FROM users WHERE ( email = ? );";
static const char sql_get_user[] = "SELECT * FROM users WHERE ( user_id = ? );";
static const char sql_add_session[] = "INSERT INTO sessions VALUES ( ?, ? );";
static const char sql_session_user[] = "SELECT user_id FROM sessions WHERE ( session_id = ? );";
static const char sql_end_session[] = "DELETE FROM sessions WHERE ( user_id = ? );";

Arena *ev_arena;

typedef U64 ID;

typedef struct User {
    ID id;
    Str username;
    Str email;
    U64 login_salt;
    U64 login_hash;
} User;

// simple ascii encoding a..=p
ID parse_id(Str str) {
    if (str.len != 16) return 0;
    U64 id = 0;
    for (size_t i = 0; i < str.len; ++i) {
        U64 c = (U64)str.buf[i];
        id |= (c - (U64)'a') << (i * 4);
    }
    return id;
}

Str format_id(Arena *arena, ID id) {
    char *str = arena_alloc(arena, 16, 1);
    for (size_t i = 0; i < 16; ++i) {
        U64 nib = (id >> (i * 4)) & 0xF;
        str[i] = (char)((U64)'a' + nib);
    }
    
    return (Str) { str, 16 };
}

int sql_bind_str(sqlite3_stmt *stmt, int index, Str str) {
    return sqlite3_bind_text(stmt, index, str.buf, (int)str.len, NULL);
}
int sql_bind_uint(sqlite3_stmt *stmt, int index, U64 n) {
    return sqlite3_bind_int64(stmt, index, (sqlite_int64)n);
}

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

void mg_http_redirect(struct mg_connection *c, const char *path) {
    const char *headers = "Content-Type: text/html; charset=utf-8\r\n";
    mg_http_reply(c, 200, headers,"<meta charset=\"utf-8\" /><meta http-equiv=\"refresh\" content=\"0; url=%s\" />", path);
    
    // StrCons sc = strcons_create(ev_arena);
    // strcons_append_t(&sc, "HX-Redirect: ");
    // strcons_append_t(&sc, path);
    // strcons_append_t(&sc, "\r\n");
    // char *header = strcons_str_t(&sc);
    // mg_http_reply(c, 200, header, "");
}

User *get_user(Arena *arena, ID id) {
    sql_ok(sql_bind_uint(stmt_get_user, 1, id));
    int ret = sqlite3_step(stmt_get_user);
    if (ret == SQLITE_DONE) {
        sql_ok(sqlite3_reset(stmt_get_user));
        return NULL;
    }
    expect(ret == SQLITE_ROW);
    
    const char *username = (const char*)sqlite3_column_text(stmt_get_user, 1);
    const char *email = (const char*)sqlite3_column_text(stmt_get_user, 2);
    U64 login_salt = (U64)sqlite3_column_int64(stmt_get_user, 3);
    U64 login_hash = (U64)sqlite3_column_int64(stmt_get_user, 4);
    
    User *user = arena_alloc(arena, sizeof(*user), alignof(*user));
    *user = (User) {
        id,
        arena_strdup_t(arena, username),
        arena_strdup_t(arena, email),
        login_salt,
        login_hash
    };
    
    sql_ok(sqlite3_reset(stmt_get_user));
    return user;
}

U64 compute_login_hash(U64 login_salt, Str password) {
    mg_sha256_ctx sha_ctx;
    mg_sha256_init(&sha_ctx);
    U64 sha[4];
    mg_sha256_update(&sha_ctx, (void*)&login_salt, sizeof(login_salt));
    mg_sha256_update(&sha_ctx, (void*)password.buf, password.len);
    mg_sha256_final((void*)&sha, &sha_ctx);
    return sha[0];
}

User *get_user_from_id_password(ID id, Str password) {
    User *user = get_user(ev_arena, id);
    if (user == NULL) return NULL;
    U64 login_hash = compute_login_hash(user->login_salt, password);
    
    if (login_hash == user->login_hash)
        return user;
    return NULL;
}

User *get_user_from_login(Str username_or_email, Str password) {
    // check ids with matching username
    {
        sql_ok(sql_bind_str(stmt_username_id, 1, username_or_email));
        User *user = NULL;
        while (1) {
            int ret = sqlite3_step(stmt_username_id);
            if (ret == SQLITE_DONE) break;
            expect(ret == SQLITE_ROW);
            ID id = (ID)sqlite3_column_int64(stmt_username_id, 0);
            user = get_user_from_id_password(id, password);
            if (user) break;
        }
        sql_ok(sqlite3_reset(stmt_username_id));
        if (user) return user;
    }

    // check ids with matching email
    {
        sql_ok(sql_bind_str(stmt_email_id, 1, username_or_email));
        User *user = NULL;
        while (1) {
            int ret = sqlite3_step(stmt_email_id);
            if (ret == SQLITE_DONE) break;
            expect(ret == SQLITE_ROW);
            ID id = (ID)sqlite3_column_int64(stmt_email_id, 0);
            user = get_user_from_id_password(id, password);
            if (user) break;
        }
        sql_ok(sqlite3_reset(stmt_email_id));
        return user;
    }
}

ID session_user(ID session_id) {
    sql_ok(sql_bind_uint(stmt_session_user, 1, session_id));
    int ret = sqlite3_step(stmt_session_user);
    if (ret == SQLITE_DONE) {
        sql_ok(sqlite3_reset(stmt_session_user));
        return 0;
    }
    expect(ret == SQLITE_ROW);
    U64 user_id = (U64)sqlite3_column_int64(stmt_session_user, 0);
    sql_ok(sqlite3_reset(stmt_session_user));
    return user_id;
}

// automatically responds
void login_user(struct mg_connection *c, Str username_or_email, Str password) {
    User *user = get_user_from_login(username_or_email, password);
    if (user == NULL) {
        mg_serve_str(c, mg_str("login details are invalid"));
        return;
    }
        
    // generate unique session_id
    ID session_id = 0;
    while (1) {
        expect(mg_random(&session_id, sizeof(session_id)));
        if (session_id == 0) continue;
        
        // ensure id doesn't exist
        sql_ok(sql_bind_uint(stmt_session_user, 1, session_id));
        int ret = sqlite3_step(stmt_session_user);
        sql_ok(sqlite3_reset(stmt_session_user));
        if (ret == SQLITE_DONE)
            break;
        expect(ret == SQLITE_ROW);
    }
    
    // insert session
    sql_ok(sql_bind_uint(stmt_add_session, 1, session_id));
    sql_ok(sql_bind_uint(stmt_add_session, 2, user->id));
    sql_done(sqlite3_step(stmt_add_session));
    sql_ok(sqlite3_reset(stmt_add_session));
    
    // set session cookie
    Str session_id_fmt = format_id(ev_arena, session_id);
    StrCons sc = strcons_create(ev_arena);
    strcons_append_t(&sc, "Content-Type: text/html; charset=utf-8\r\n");
    strcons_append_t(&sc, "Set-Cookie: session_id=");
    strcons_append(&sc, session_id_fmt);
    #ifdef PROD
        strcons_append_t(&sc, "; Secure; Path=/; HttpOnly; SameSite=Lax\r\n");
    #else
        // SameSite=Lax doesn't work on localhost, idk why
        strcons_append_t(&sc, "; Path=/\r\n");
    #endif
    char *headers = strcons_str_t(&sc);
    
    // navigate to base app
    mg_http_reply(c, 200, headers, "<meta charset=\"utf-8\" /><meta http-equiv=\"refresh\" content=\"0; url=/\" />");
}

// automatically responds
void signup_user(struct mg_connection *c, Str username, Str email, Str password) {
    // TODO validation
    
    // TODO ensure email isn't used

    // generate salt
    U64 login_salt;
    expect(mg_random(&login_salt, sizeof(login_salt)));
    
    // compute password hash
    U64 login_hash = compute_login_hash(login_salt, password);
    
    // generate id
    ID id = 0;
    while (1) {
        expect(mg_random(&id, sizeof(id)));
        if (id == 0) continue;
        
        // ensure id doesn't exist
        sql_ok(sql_bind_uint(stmt_get_user, 1, id));
        int ret = sqlite3_step(stmt_get_user);
        sql_ok(sqlite3_reset(stmt_get_user));
        if (ret == SQLITE_DONE)
            break;
        expect(ret == SQLITE_ROW);
    }
    
    // insert user
    sql_ok(sql_bind_uint(stmt_signup, 1, id));
    sql_ok(sql_bind_str(stmt_signup, 2, username));
    sql_ok(sql_bind_str(stmt_signup, 3, email));
    sql_ok(sql_bind_uint(stmt_signup, 4, login_salt));
    sql_ok(sql_bind_uint(stmt_signup, 5, login_hash));
    sql_done(sqlite3_step(stmt_signup));
    sql_ok(sqlite3_reset(stmt_signup));
    
    // login user after signup
    login_user(c, email, password);
}

void logout_user(struct mg_connection *c, ID user_id) {
    sql_ok(sql_bind_uint(stmt_end_session, 1, user_id));
    sql_done(sqlite3_step(stmt_end_session));
    sql_ok(sqlite3_reset(stmt_end_session));

    // navigate back to base app
    
    const char *headers = "Content-Type: text/html; charset=utf-8\r\n";
    mg_http_reply(c, 200, headers, "<meta charset=\"utf-8\" /><meta http-equiv=\"refresh\" content=\"0; url=/\" />");
}

void post_message(ID id, Str message) {
    sql_ok(sql_bind_uint(stmt_post_message, 1, id));
    sql_ok(sql_bind_str(stmt_post_message, 2, message));
    sql_done(sqlite3_step(stmt_post_message));
    sql_ok(sqlite3_reset(stmt_post_message));
}

Str read_history(Arena *arena) {
    StrCons sc = strcons_create(arena);
    
    strcons_append_t(&sc, "<div id=\"chat\">");
    
    while (1) {
        int ret = sqlite3_step(stmt_read_history);
        if (ret == SQLITE_DONE) break;
        expect(ret == SQLITE_ROW);
        
        const char *username = (const char*)sqlite3_column_text(stmt_read_history, 0);
        const char *message = (const char*)sqlite3_column_text(stmt_read_history, 1);
        
        strcons_append_t(&sc, username);
        strcons_append_t(&sc, ": ");
        strcons_append_t(&sc, message);
        strcons_append_t(&sc, "<br>");
    }
    
    strcons_append_t(&sc, "</div>");
    expect(sqlite3_reset(stmt_read_history) == SQLITE_OK);
    
    return strcons_str(&sc);
}

typedef struct ConnData {
    bool is_ws;
    
    union {
        struct {
            ID user_id;
        } ws;
    };
} ConnData;

ConnData *conn_data(struct mg_connection *c) {
    expect(sizeof(ConnData) <= MG_DATA_SIZE);
    return (ConnData *)c->data;
}

void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        arena_clear(ev_arena);
        
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        struct mg_http_serve_opts opts = { .root_dir = "./web_root/" };
        
        mg_print_str("URI: ", hm->uri);
        
        ID session_id = 0;
        ID user_id = 0;
        Str *cookie = mg_http_get_header(hm, "Cookie");
        if (cookie) {
            Str session_id_fmt = mg_http_var(*cookie, mg_str("session_id"));
            session_id = parse_id(session_id_fmt);
            
            if (session_id)
                user_id = session_user(session_id);
        }
        
        if (mg_match(hm->uri, mg_str("/ws"), NULL)) {
            if (user_id != 0) {
                User *user = get_user(ev_arena, user_id);
                if (user == NULL)
                    goto INVALID_HS;
                
                mg_ws_upgrade(c, hm, NULL);
                ConnData *c_data = conn_data(c);
                c_data->is_ws = true;
                c_data->ws.user_id = user_id;
                
                // send user info
                StrCons sc = strcons_create(ev_arena);
                strcons_append_t(&sc, "<div id=\"user-info\">");
                strcons_append_t(&sc, "<div id=\"username\">");
                strcons_append(&sc, user->username);
                strcons_append_t(&sc, "</div>");
                strcons_append_t(&sc, "</div>");
                Str user_info = strcons_str(&sc);
                mg_ws_send(c, user_info.buf, user_info.len, WEBSOCKET_OP_TEXT);
                
                // send chat history
                Str ws_chat = read_history(ev_arena);
                mg_ws_send(c, ws_chat.buf, ws_chat.len, WEBSOCKET_OP_TEXT);
            } else {
                mg_http_redirect(c, "login");
            }
        }
        else if (mg_match(hm->uri, mg_str("/"), NULL)) {
            if (user_id == 0) {
                // not logged in - show login html
                mg_http_redirect(c, "login");
            } else {
                // logged in - show app
                mg_http_serve_file(c, hm, "web_root/base.html", &opts);
            }
        }
        else if (mg_match(hm->uri, mg_str("/login"), NULL)) {
            mg_http_serve_file(c, hm, "web_root/login.html", &opts);
        }
        else if (mg_match(hm->uri, mg_str("/login-user"), NULL)) {
            Str username_or_email = mg_http_var(hm->body, mg_str("username_or_email"));
            Str password = mg_http_var(hm->body, mg_str("password"));
            if (str_null(username_or_email)) goto INVALID_HS;
            if (str_null(password)) goto INVALID_HS;
            
            login_user(c, username_or_email, password);
        }
        else if (mg_match(hm->uri, mg_str("/signup"), NULL)) {
            mg_http_serve_file(c, hm, "web_root/signup.html", &opts);
        }
        else if (mg_match(hm->uri, mg_str("/signup-user"), NULL)) {
            Str username = mg_http_var(hm->body, mg_str("username"));
            Str email = mg_http_var(hm->body, mg_str("email"));
            Str password = mg_http_var(hm->body, mg_str("password"));
            if (str_null(username)) goto INVALID_HS;
            if (str_null(email)) goto INVALID_HS;
            if (str_null(password)) goto INVALID_HS;
            
            signup_user(c, username, email, password);
        }
        else if (mg_match(hm->uri, mg_str("/logout"), NULL)) {
            if (user_id)
                logout_user(c, user_id);
            else
                goto INVALID_HS;
        }
        else if (mg_match(hm->uri, mg_str("/htmx.js"), NULL)) {
            mg_http_serve_file(c, hm, "web_root/htmx.js", &opts);
        }
        else if (mg_match(hm->uri, mg_str("/htmx-ws.js"), NULL)) {
            mg_http_serve_file(c, hm, "web_root/htmx-ws.js", &opts);
        } else {
            printf("Unhandled URI!\n");
            mg_http_reply(c, 404, NULL, "");
        }
        
        return;
        INVALID_HS:
        mg_bad_request(c);
    }
    else if (ev == MG_EV_WS_MSG) {
        arena_clear(ev_arena);
        
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
        
        char *task = mg_json_get_str(wm->data, "$.HEADERS.HX-Target");
        if (task == NULL) goto INVALID_WS;
        
        if (strcmp(task, "post-message") == 0) {
            Str message = str_create(mg_json_get_str(wm->data, "$.message"));
            ConnData *c_data = conn_data(c);
            ID user_id = c_data->ws.user_id;
            
            if (str_null(message)) goto INVALID_WS;
            post_message(user_id, message);
            
            Str ws_chat = read_history(ev_arena);
            for (struct mg_connection *wc = c->mgr->conns; wc != NULL; wc = wc->next) {
                ConnData *wc_data = conn_data(wc);
                if (wc_data->is_ws)
                    mg_ws_send(wc, ws_chat.buf, ws_chat.len, WEBSOCKET_OP_TEXT);
            }
        }
        return;
        
        INVALID_WS:
        mg_print_str("INVALID WS: ", wm->data);
    }
}

int main(void) {
    // INIT --------------------------------------------
    
    expect(sqlite3_open_v2("db.sqlite", &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
    
    sql_ok(sqlite3_prepare_v2(db, sql_post_message, sizeof(sql_post_message), &stmt_post_message, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_login, sizeof(sql_login), &stmt_login, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_signup, sizeof(sql_signup), &stmt_signup, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_read_history, sizeof(sql_read_history), &stmt_read_history, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_username_id, sizeof(sql_username_id), &stmt_username_id, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_email_id, sizeof(sql_email_id), &stmt_email_id, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_get_user, sizeof(sql_get_user), &stmt_get_user, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_add_session, sizeof(sql_add_session), &stmt_add_session, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_session_user, sizeof(sql_session_user), &stmt_session_user, NULL));
    sql_ok(sqlite3_prepare_v2(db, sql_end_session, sizeof(sql_end_session), &stmt_end_session, NULL));
    
    Arena arena = arena_create(1ull << 30ull); // 1gb
    ev_arena = &arena;
    
    // RUN SERVER ------------------------------------------

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:10000", ev_handler, NULL);
    while (true) {
        mg_mgr_poll(&mgr, -1);
    }
    
    return 0;
}
