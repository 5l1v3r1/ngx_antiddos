/*
 * HTTP anti-ddos nginx module
 *
 * Marek Aufart, aufi.cz@gmail.com
 *
 * Visit project page: https://github.com/aufi/anddos
 *
 * license: GNU GPL v3
 *
 * resources: http://wiki.nginx.org/3rdPartyModules,
 * http://www.evanmiller.org/nginx-modules-guide.html,
 * http://blog.zhuzhaoyuan.com/2009/08/creating-a-hello-world-nginx-module/
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <time.h>

#define HASHKEYLEN 250
#define HASHTABLESIZE 10240      //100k in production
#define STATE_FILE "/tmp/anddos_state"
#define SEQSIZE 32
#define INITTHRESHOLD 160
#define DEBUG 1

//function declarations
static ngx_int_t ngx_http_anddos_request_handler(ngx_http_request_t *r);

static char *ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_anddos_learn_filter(ngx_http_request_t *r);

static ngx_int_t ngx_http_anddos_filter_init(ngx_conf_t *cf);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

ngx_int_t set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value);

unsigned int ngx_http_anddos_get_client_index(ngx_http_request_t *r);

void ngx_http_anddos_get_client_text(u_char *text_key, ngx_http_request_t *r);
//static char * ngx_http_anddos_rnd_text();
//static int ngx_http_anddos_hash_get_adr(char * t); //or  ngx_hash_key(u_char *data, size_t len)

//data store
//struct ngx_http_anddos_client;
//struct ngx_http_anddos_state;

//anddos internal functions
//static char * ngx_http_anddos_get_state();
//static char * ngx_http_anddos_get_client();

//datatypes
static ngx_command_t ngx_http_anddos_commands[] = {
        {
          ngx_string("anddos"),
          NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
          ngx_http_anddos,
          0,
          0,
          NULL
        },
        ngx_null_command
};

static ngx_http_module_t ngx_http_anddos_module_ctx = {
        NULL, /* preconfiguration */
        ngx_http_anddos_filter_init, /* postconfiguration */
        NULL, /* create main configuration */
        NULL, /* init main configuration */
        NULL, /* create server configuration */
        NULL, /* merge server configuration */
        NULL, /* create location configuration */
        NULL /* merge location configuration */
};

ngx_module_t ngx_http_anddos_module = {
        NGX_MODULE_V1,
        &ngx_http_anddos_module_ctx, /* module context */
        ngx_http_anddos_commands, /* module directives */
        NGX_HTTP_MODULE, /* module type */
        NULL, /* init master */
        NULL, /* init module */
        NULL, /* init process */
        NULL, /* init thread */
        NULL, /* exit thread */
        NULL, /* exit process */
        NULL, /* exit master */
        NGX_MODULE_V1_PADDING
};

typedef struct { //FIX keep IP somewhere for blocking all clients from the IP
    unsigned char set; // -> bool
    unsigned int banned;

    unsigned int request_count; // ensure that int overflow will not occur errors
    unsigned int notmod_count;
    unsigned int http1_count;
    unsigned int http2_count;
    unsigned int http3_count;
    unsigned int http4_count;
    unsigned int http5_count;
    unsigned int avg_time; // rounding is OK
    unsigned int html_avg_time;
    unsigned int key;

    //mimetypes count
    unsigned int html_count;
    unsigned int assets_count; // or just text?
    unsigned int json_count;
    unsigned int other_count; // FIX necesarry?

    //scores
    unsigned int httpcode_score;
    unsigned int mimetype_score;
    unsigned int time_score;
    unsigned int passeq_score;

    u_char pass_seq[SEQSIZE];
    u_char ip[HASHKEYLEN];

} ngx_http_anddos_client_t;

typedef struct {
    unsigned int threshold;

    unsigned int request_count;
    unsigned int notmod_count;
    unsigned int http1_count;
    unsigned int http2_count;
    unsigned int http3_count;
    unsigned int http4_count;
    unsigned int http5_count;
    unsigned int client_count;
    unsigned int avg_time;
    unsigned int html_avg_time;

    //mimetypes count
    unsigned int html_count;
    unsigned int assets_count;
    unsigned int json_count;
    unsigned int other_count;

} ngx_http_anddos_state_t;


//data init
ngx_http_anddos_client_t ngx_http_anddos_clients[HASHTABLESIZE];
ngx_http_anddos_state_t ngx_http_anddos_state;


//http://wiki.nginx.org/HeadersManagement

ngx_int_t
set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value) {
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->key = *key;
    h->value = *value;
    h->hash = 1;

    return NGX_OK;
}

static ngx_int_t ngx_http_anddos_request_handler(ngx_http_request_t *r) {
    // disabled while using proxy_pass directive, due to nginx architecture
    // this handler can block requests only for static content on local server
    // @TODO: FIX spread blocking to all requests
    if(ngx_strcmp(r->connection->addr_text.data, "127.0.0.1") == 0){
      return NGX_DECLINED;
    }
    if (DEBUG)
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS processing request");
    ngx_int_t rc;

    //DECIDE whether is request bot or not
    //KISS, one condition, rest logic is moved to the learn_filter

    u_char text_key[HASHKEYLEN];
    memset(text_key, 0, HASHKEYLEN);
    ngx_http_anddos_get_client_text(text_key, r);
    unsigned int key = ngx_hash_key(text_key, ngx_strlen(text_key)) % HASHTABLESIZE;

    if( (int) ngx_http_anddos_clients[key].banned >= (int)time(NULL) ) {
      if (DEBUG)
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS BANNED CLIENT - DROPPED");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // @TODO: configuration
    if (*ngx_stat_active <= 50  || (int) ngx_http_anddos_clients[key].set < 2) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS: request blocked");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

void
ngx_http_anddos_get_client_text(u_char *text_key, ngx_http_request_t *r) {
    ngx_snprintf(text_key, (int) r->connection->addr_text.len, "%s", r->connection->addr_text.data);
}

void
ngx_http_anddos_clients_stats(ngx_http_request_t *r) {

    int i;

    //log
    if (DEBUG) {
        for (i = 0; i < HASHTABLESIZE; i++) {
            if (ngx_http_anddos_clients[i].set > 0) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "ANDDOS client[%d]: request_count: %d; http200_count: %d, key: %d, avg_time: %d, pass_seq: %s",
                              i, ngx_http_anddos_clients[i].request_count, ngx_http_anddos_clients[i].http2_count,
                              ngx_http_anddos_clients[i].key, ngx_http_anddos_clients[i].avg_time,
                              (char *) ngx_http_anddos_clients[i].pass_seq);
            }
        }
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "ANDDOS state: request_count: %d; http200_count: %d, client_count: %d, avg_time: %d",
                      ngx_http_anddos_state.request_count, ngx_http_anddos_state.http2_count,
                      ngx_http_anddos_state.client_count, ngx_http_anddos_state.avg_time);
        //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS mimetypes: html: %d; css: %d, js: %d, images: %d, other: %d", ngx_http_anddos_state.html_count, ngx_http_anddos_state.css_count, ngx_http_anddos_state.javascript_count, ngx_http_anddos_state.image_count, ngx_http_anddos_state.other_count);
    }

    //DEV logging anddos state to file (after 1/100reqs)
    if ((ngx_http_anddos_state.request_count % 100) != 2)
      return;

    //else stats to file
    FILE *f;
    if (!(f = freopen(STATE_FILE, "w", stdout))) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS error: save to file failed");
    } else {
        printf("ANDDOS state\nthreshold clients reqs 304cnt http1cnt http2cnt http3cnt http4cnt http5cnt avgtime htmlavgtime html assets json other\n");
        printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
               ngx_http_anddos_state.threshold, ngx_http_anddos_state.client_count,
               ngx_http_anddos_state.request_count, ngx_http_anddos_state.notmod_count,
               ngx_http_anddos_state.http1_count, ngx_http_anddos_state.http2_count, ngx_http_anddos_state.http3_count,
               ngx_http_anddos_state.http4_count, ngx_http_anddos_state.http5_count,
               ngx_http_anddos_state.avg_time, ngx_http_anddos_state.html_avg_time, ngx_http_anddos_state.html_count,
               ngx_http_anddos_state.assets_count, ngx_http_anddos_state.json_count, ngx_http_anddos_state.other_count);

        printf("ANDDOS clients\nset index httpscore mimescore timescore seqscore reqs 304_cnt http1cnt http2cnt http3cnt http4cnt http5cnt avgtime htmlavgtime html assets json other pass_seq    ip\n");
        for (i = 0; i < HASHTABLESIZE; i++) {
            if ((int) ngx_http_anddos_clients[i].set > 0) {
                printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n",
                       (int) ngx_http_anddos_clients[i].set, i, ngx_http_anddos_clients[i].httpcode_score,
                       ngx_http_anddos_clients[i].mimetype_score, ngx_http_anddos_clients[i].time_score,
                       ngx_http_anddos_clients[i].passeq_score,
                       ngx_http_anddos_clients[i].request_count, ngx_http_anddos_clients[i].notmod_count,
                       ngx_http_anddos_clients[i].http1_count, ngx_http_anddos_clients[i].http2_count,
                       ngx_http_anddos_clients[i].http3_count, ngx_http_anddos_clients[i].http4_count,
                       ngx_http_anddos_clients[i].http5_count,
                       ngx_http_anddos_clients[i].avg_time, ngx_http_anddos_clients[i].html_avg_time,
                       ngx_http_anddos_clients[i].html_count, ngx_http_anddos_clients[i].assets_count,
                       ngx_http_anddos_clients[i].json_count, ngx_http_anddos_clients[i].other_count,
                       (char *) ngx_http_anddos_clients[i].pass_seq,
                       (char *) ngx_http_anddos_clients[i].ip);
            }
        }
        fclose(f);
    }
}

int ngx_http_anddos_get_msec(ngx_http_request_t *r) {
    // inspired by logmodule msec function
    int ms;
    ngx_time_t *tp;

    tp = ngx_timeofday();

    ms = ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = ngx_max(ms, 0);

    return ms;
}

inline void ngx_http_anddos_set_mimetype_stats(ngx_http_request_t *r, int key, int request_time) {

    if ((int) r->headers_out.status >= 300 ||
        (int) r->headers_out.status < 200) { //exclude no success (<>200) responses
        return;
    }

    int cnt = 0;
    int isAsset = 0;
    u_char mime_type[32];
    memset(mime_type, 0, 32);
    ngx_snprintf(mime_type, r->headers_out.content_type.len, "%s", r->headers_out.content_type.data);

    if (DEBUG)
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS mime: %s (active: %d)", mime_type, *ngx_stat_active);

    if (ngx_strstr(mime_type, "text/html") != NULL) {
        ngx_http_anddos_clients[key].html_count += 1;
        ngx_http_anddos_state.html_count += 1;

        ngx_http_anddos_state.html_avg_time =
                (ngx_http_anddos_state.html_avg_time * (ngx_http_anddos_state.html_count - 1) + request_time) /
                ngx_http_anddos_state.html_count;
        ngx_http_anddos_clients[key].html_avg_time =
                (ngx_http_anddos_clients[key].html_avg_time * (ngx_http_anddos_clients[key].html_count - 1) +
                 request_time) / ngx_http_anddos_clients[key].html_count;
    } else {
        // not count all request_count, but only non 304 and non html
        // ngx_http_anddos_state.avg_time = ngx_http_anddos_state.avg_time * (ngx_http_anddos_state.request_count - ngx_http_anddos_state.notmod_count - 1) / (ngx_http_anddos_state.request_count - ngx_http_anddos_state.notmod_count) + request_time / (ngx_http_anddos_state.request_count - ngx_http_anddos_state.notmod_count);
        // ngx_http_anddos_clients[key].avg_time = ngx_http_anddos_clients[key].avg_time * (ngx_http_anddos_clients[key].request_count - 1) / ngx_http_anddos_clients[key].request_count + request_time / ngx_http_anddos_clients[key].request_count;
        // is better to risk overflow or rounding ? :)
        cnt = ngx_http_anddos_state.http2_count - ngx_http_anddos_state.html_count;
        if (cnt == 0) {
            ngx_http_anddos_state.avg_time = 0;
        } else {
            ngx_http_anddos_state.avg_time = (ngx_http_anddos_state.avg_time * (cnt - 1) + request_time) / cnt;
        }
        cnt = ngx_http_anddos_clients[key].http2_count - ngx_http_anddos_clients[key].html_count;
        if (cnt == 0) {
            ngx_http_anddos_clients[key].avg_time = 0;
        } else {
            ngx_http_anddos_clients[key].avg_time =
                  (ngx_http_anddos_clients[key].avg_time * (cnt - 1) + request_time) / cnt;
        }

        //what about browser's cache, maybe understand to http headers ?
        isAsset = (ngx_strstr(mime_type, "image/") != NULL) ||
                  (ngx_strstr(mime_type, "javascript") != NULL) ||
                  (ngx_strstr(mime_type, "css") != NULL);

        if (isAsset) {
            ngx_http_anddos_clients[key].assets_count += 1;
            ngx_http_anddos_state.assets_count += 1;
        } else if (ngx_strstr(mime_type, "json") != NULL) {
            ngx_http_anddos_clients[key].json_count += 1;
            ngx_http_anddos_state.json_count += 1;
        } else {
            ngx_http_anddos_clients[key].other_count += 1;
            ngx_http_anddos_state.other_count += 1;
        }
    }
}

inline void
ngx_http_anddos_set_httpcode_stats(ngx_http_request_t *r, int key) {

    //FIX 3xx or keep 304 as a special code, which proofs that client has a local cache? 2012-03-28 keep!

    int code = (int) r->headers_out.status;

    if (code == 304) {
        ngx_http_anddos_clients[key].notmod_count += 1;
        ngx_http_anddos_state.notmod_count += 1;
    }

    if (code < 200) {
        ngx_http_anddos_clients[key].http1_count += 1;
        ngx_http_anddos_state.http1_count += 1;
    } else if (code < 300) {       //we keep all 3xx (incl.304)
        ngx_http_anddos_clients[key].http2_count += 1;
        ngx_http_anddos_state.http2_count += 1;
    } else if (code < 400) {
        ngx_http_anddos_clients[key].http3_count += 1;
        ngx_http_anddos_state.http3_count += 1;
    } else if (code < 500) {
        ngx_http_anddos_clients[key].http4_count += 1;
        ngx_http_anddos_state.http4_count += 1;
    } else {
        ngx_http_anddos_clients[key].http5_count += 1;
        ngx_http_anddos_state.http5_count += 1;
    }

}

inline float
ngx_http_anddos_count_fdiff(float global, float client) {
    //what about attack by many very fast and not "heavy" reqs ..no reason to do that, but better block both extrems

    if (global == 0)
      return 0;

    if (client > global)
        return (client - global) / global;       // or non-linear math function => exp ?
    else
        return (global - client) / global;
}

inline unsigned int
ngx_http_anddos_count_diff(unsigned int global, unsigned int client) {

    // if (global == 0) return 0;
    // return abs(client - global) / global;       //or non-linear math function - log/exp ?

    return (int) 100 * ngx_http_anddos_count_fdiff((float) global, (float) client);
}

void
ngx_http_anddos_undo_stats(int key) {
  ngx_http_anddos_state.notmod_count -= ngx_http_anddos_clients[key].notmod_count;
  ngx_http_anddos_state.http1_count -= ngx_http_anddos_clients[key].http1_count;
  ngx_http_anddos_state.http2_count -= ngx_http_anddos_clients[key].http2_count;
  ngx_http_anddos_state.http3_count -= ngx_http_anddos_clients[key].http3_count;
  ngx_http_anddos_state.http4_count -= ngx_http_anddos_clients[key].http4_count;
  ngx_http_anddos_state.http5_count -= ngx_http_anddos_clients[key].http5_count;

  // @TODO: ngx_http_anddos_state.avg_time ?
}

int
ngx_http_anddos_decide(ngx_http_request_t *r, int key) {
    // take a decision
    // if client's param differs to global param by more than threshold, block
    // threshold depends on reqs count, global state, statistic function
    // scores are kept from time, when last request was served (->first client)

    int dec;
    dec = 1;

    unsigned int score = ngx_http_anddos_clients[key].httpcode_score + ngx_http_anddos_clients[key].mimetype_score +
                         ngx_http_anddos_clients[key].time_score;

    if (score > ngx_http_anddos_state.threshold && ngx_http_anddos_clients[key].request_count > 5)
      dec = 2;

    //when block some client compensate global stats by opposite values of his params
    if (ngx_http_anddos_clients[key].set == 1 && dec == 2) {
      ngx_http_anddos_undo_stats(key);
    }

    return dec;
}


inline unsigned int
ngx_http_anddos_count_score_time(unsigned int c_avg, unsigned int c_html) {
    return (int) ((ngx_http_anddos_count_diff(ngx_http_anddos_state.avg_time, c_avg) +
                   ngx_http_anddos_count_diff(ngx_http_anddos_state.html_avg_time, c_html)) / 2);
}

inline unsigned int
ngx_http_anddos_count_score_mimetype(unsigned int cnt, unsigned int html, unsigned int assets, unsigned int other) {

    float w1 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.html_count / ngx_http_anddos_state.request_count, (float) html / cnt);
    float w2 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.assets_count / ngx_http_anddos_state.request_count, (float) assets / cnt);
    float w4 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.other_count / ngx_http_anddos_state.request_count, (float) other / cnt);

    //or weighted sum ?
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS score[%d]: %d %d %d %d %d", w1, w2, w3, w4, w5);

    return (int) (100 * (w1 + w2 + w4));      //lost precision?
}

inline unsigned int
ngx_http_anddos_count_score_httpcode(unsigned int cnt, unsigned int c1, unsigned int c2, unsigned int c3,
                                     unsigned int c4, unsigned int c5) {

    float w1 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.http1_count / ngx_http_anddos_state.request_count, (float) c1 / cnt);
    float w2 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.http2_count / ngx_http_anddos_state.request_count, (float) c2 / cnt);
    float w3 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.http3_count / ngx_http_anddos_state.request_count, (float) c3 / cnt);
    float w4 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.http4_count / ngx_http_anddos_state.request_count, (float) c4 / cnt);
    float w5 = ngx_http_anddos_count_fdiff(
            (float) ngx_http_anddos_state.http5_count / ngx_http_anddos_state.request_count, (float) c5 / cnt);

    //or weighted sum ?
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS score[%d]: %d %d %d %d %d", w1, w2, w3, w4, w5);

    return (int) (100 * (w1 + w2 + w3 + w4 + w5));      //lost precision?
}

void
ngx_http_anddos_count_scores(ngx_http_request_t *r, int key) {

    //httpcode
    ngx_http_anddos_clients[key].httpcode_score = ngx_http_anddos_count_score_httpcode(
            ngx_http_anddos_clients[key].request_count, ngx_http_anddos_clients[key].http1_count,
            ngx_http_anddos_clients[key].http2_count,
            ngx_http_anddos_clients[key].http3_count, ngx_http_anddos_clients[key].http4_count,
            ngx_http_anddos_clients[key].http5_count
    );

    //mimetype
    ngx_http_anddos_clients[key].mimetype_score = ngx_http_anddos_count_score_mimetype(
            ngx_http_anddos_clients[key].request_count,
            ngx_http_anddos_clients[key].html_count,
            ngx_http_anddos_clients[key].assets_count,
            ngx_http_anddos_clients[key].other_count
    );

    //time
    ngx_http_anddos_clients[key].time_score = ngx_http_anddos_count_score_time(ngx_http_anddos_clients[key].avg_time,
                                                                               ngx_http_anddos_clients[key].html_avg_time);

    //passeq
    //count of unique paths, what globally??
}

inline int
ngx_http_anddos_count_threshold() {

    if (ngx_http_anddos_state.request_count < 37 || ngx_http_anddos_state.client_count < 5)
      return INITTHRESHOLD;

    int i, min, max, clients;
    float avg;
    min = INITTHRESHOLD;
    max = 0;
    avg = 0;
    clients = 0;

    for (i = 0; i < HASHTABLESIZE; i++) {

        if ((int) ngx_http_anddos_clients[i].set == 1 && (int) ngx_http_anddos_clients[i].request_count > 1) {
            clients += 1;
            int score = ngx_http_anddos_clients[i].httpcode_score + ngx_http_anddos_clients[i].mimetype_score +
                        ngx_http_anddos_clients[i].time_score;
            if (score < min)
              min = score;
            if (score > max)
              max = score;
            avg = (avg * (clients - 1) + score) / clients;
        }
    }
    // FIX maybe naive?
    // FIX2 also global state (normal/attack) can be concerned
    return 150 + avg;     // 2x is too much, 100+ seems to be ok, update: 150 + avg seems to be the best (measures)

}

static ngx_int_t
ngx_http_anddos_learn_filter(ngx_http_request_t *r) {
    // the client data
    u_char text_key[HASHKEYLEN];
    memset(text_key, 0, HASHKEYLEN);
    ngx_http_anddos_get_client_text(text_key, r);
    unsigned int key = ngx_hash_key(text_key, ngx_strlen(text_key)) % HASHTABLESIZE;
    int request_time = ngx_http_anddos_get_msec(r);

    // server stats update
    ngx_http_anddos_state.request_count += 1;
    // first req let pass (in normal conditions)


    if ((int) ngx_http_anddos_clients[key].set == 0) {
        //setup in client hashtable
        ngx_http_anddos_clients[key].set = 1;
        ngx_http_anddos_clients[key].banned = 0;
        ngx_http_anddos_clients[key].request_count = 1;
        ngx_http_anddos_get_client_text(ngx_http_anddos_clients[key].ip, r);
        ngx_http_anddos_clients[key].pass_seq[0] = (u_char)(ngx_hash_key(r->uri.data, r->uri.len) % 94 + 33); //printable chars from ascii //circ.register will differ same sequentions (longer than SEQSTEPS)

        if (DEBUG)
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS client[%d]: step id: %c for uri: %s",
                          key,
                          (char) ngx_http_anddos_clients[key].pass_seq[0],
                          (char *) r->uri.data);

        ngx_http_anddos_set_httpcode_stats(r, key);

        ngx_http_anddos_set_mimetype_stats(r, key, request_time);

        ngx_http_anddos_state.client_count += 1;

    } else {

        // dont count to stats already blocked clients
        // FIX (should not be here in production, but useful for development and testing purposes)
        if (ngx_http_anddos_clients[key].set > 1)
          return ngx_http_next_header_filter(r); // DEV FIX


        //web-pass sequence
        //ngx_http_anddos_clients[key].pass_seq[ngx_http_anddos_clients[key].request_count % (SEQSIZE - 1)] = (u_char) (ngx_hash_key(r->uri.data, r->uri.len) % 94 + 33);    //circ.register will differ same sequentions (longer than SEQSTEPS)
        if (ngx_http_anddos_clients[key].request_count < (SEQSIZE - 1)) { //register for first n requested url hashes
            ngx_http_anddos_clients[key].pass_seq[ngx_http_anddos_clients[key].request_count] = (u_char)(
                    ngx_hash_key(r->uri.data, r->uri.len) % 94 + 33);
        }

        ngx_http_anddos_clients[key].request_count += 1;

        if (DEBUG)
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS client[%d]: step id: %c for uri: %s",
                          key,
                          (char) ngx_http_anddos_clients[key].pass_seq[ngx_http_anddos_clients[key].request_count %
                                                                       SEQSIZE],
                          (char *) r->uri.data);

        ngx_http_anddos_set_httpcode_stats(r, key);

        ngx_http_anddos_set_mimetype_stats(r, key, request_time);

        ngx_http_anddos_count_scores(r, key);

        // DECIDE to BLOCK
        // and export blocked IP somewhere?
        ngx_http_anddos_clients[key].set = ngx_http_anddos_decide(r, key);
        if(ngx_http_anddos_clients[key].set == 2) {
          if (DEBUG)
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS BANNING CLIENT");
          ngx_http_anddos_clients[key].banned = (int)time(NULL) + 600;
        }

    }

    // if ((ngx_http_anddos_state.request_count % 100) != 37)
    ngx_http_anddos_state.threshold = ngx_http_anddos_count_threshold();  // always in dev/test env

    ngx_http_anddos_clients_stats(r);

    return ngx_http_next_header_filter(r);
}

// initializers

static char *
ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_anddos_request_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_anddos_filter_init(ngx_conf_t *cf) {
    // FIX handles all requests (incl.blocked)!
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_anddos_learn_filter;

    // dont reinit table in case of worker process fail
    if ((int) ngx_http_anddos_state.client_count > 0) {
        return NGX_OK;
    }

    // basic server stats
    ngx_http_anddos_state.threshold = INITTHRESHOLD;
    ngx_http_anddos_state.client_count = 0;

    // clean clients list
    int i;
    for (i = 0; i < HASHTABLESIZE; i++) {
        ngx_http_anddos_clients[i].set = 0;
        ngx_http_anddos_clients[i].banned = 0;

        memset(ngx_http_anddos_clients[i].ip, 0, HASHKEYLEN);
        memset(ngx_http_anddos_clients[i].pass_seq, 0, SEQSIZE);
    }

    // dev print hashtable size
    printf("ANDDOS hashtable size: %ld B\n", (long int) sizeof(ngx_http_anddos_clients));

    return NGX_OK;
}
