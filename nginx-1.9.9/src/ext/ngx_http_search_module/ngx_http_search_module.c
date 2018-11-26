#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
typedef struct {
    ngx_str_t output_words;
} ngx_http_hello_world_loc_conf_t;

typedef struct {
    ngx_int_t idx;
} ngx_http_hello_world_ctx_t;

ngx_int_t ngx_http_hello_world_idx;
static char *ngx_http_hello_world(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_hello_world_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hello_world_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_hello_world_commands[] = {
    { ngx_string("search"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_hello_world,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hello_world_loc_conf_t, output_words),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_hello_world_module_ctx = {
    NULL,     
    NULL,     

    NULL,     
    NULL,     

    NULL,     
    NULL,     

    ngx_http_hello_world_create_loc_conf,

    ngx_http_hello_world_merge_loc_conf

};

ngx_int_t ngx_http_hello_world_init_master(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_WARN, log, 0, "init master\n");  
    ngx_http_hello_world_idx = 100000;
    return NGX_OK;
}

ngx_int_t ngx_http_hello_world_init_module(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "init module\n");  
    return NGX_OK;
}

ngx_int_t ngx_http_hello_world_exit_module(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "exit module\n");  
    return NGX_OK;
}

ngx_int_t ngx_http_hello_world_init_thread(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "init thread\n");  
    return NGX_OK;
}

void ngx_http_hello_world_exit_thread(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "exit thread\n");  
    return;
}

ngx_int_t ngx_http_hello_world_init_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "init process\n");  
    return NGX_OK;
}

void ngx_http_hello_world_exit_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "exit process\n");  
    return;
}

void ngx_http_hello_world_exit_master(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "exit master\n");  
    return;
}

ngx_module_t ngx_http_hello_world_module = {
    NGX_MODULE_V1,
    &ngx_http_hello_world_module_ctx,
    ngx_http_hello_world_commands,
    NGX_HTTP_MODULE,
    ngx_http_hello_world_init_master,
    ngx_http_hello_world_init_module,
    ngx_http_hello_world_init_process,
    ngx_http_hello_world_init_thread,  /*Jack:什么时候被掉用?*/
    ngx_http_hello_world_exit_thread,  /*Jack:什么时候被掉用?*/
    ngx_http_hello_world_exit_process,
    ngx_http_hello_world_exit_master,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_hello_world_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_hello_world_ctx_t *ctx;
    char c_stats[100];
    ngx_buf_t *b;
    ngx_chain_t out[4];

    ngx_http_hello_world_loc_conf_t *hlcf;
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[0].buf = b;
    out[0].next = &out[1];

    b->pos = (u_char *) "hello_world, ";
    b->last = b->pos + sizeof("hello_world, ") - 1;
    b->memory = 1;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[1].buf = b;
    out[1].next = &out[2];

    b->pos = hlcf->output_words.data;
    b->last = hlcf->output_words.data + (hlcf->output_words.len);
    b->memory = 1;
    b->last_buf = 0;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    out[2].buf = b;
    out[2].next = &out[3];
    b->pos = (u_char *)"\n";
    b->last = b->pos + 1;
    b->memory = 1;
    b->last_buf = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_world_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can not find context\n");
        return NGX_ERROR;
    }
    memset(c_stats, 0, sizeof(c_stats));
    sprintf(c_stats, "You are the %lu person!\n", ctx->idx);

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    out[3].buf = b;
    out[3].next = NULL;
    b->pos = (u_char *)c_stats;
    b->last = b->pos + strlen(c_stats);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = hlcf->output_words.len
        + sizeof("hello_world, ") + strlen(c_stats);
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out[0]);
}

static void *
ngx_http_hello_world_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hello_world_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_world_loc_conf_t));
    if (conf == NULL)
    {
        return NGX_CONF_ERROR;
    }
    conf->output_words.len = 0;

    conf->output_words.data = NULL;

    return conf;
}

/* Jack: by default replace the parent with child configuration */
static char *
ngx_http_hello_world_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hello_world_loc_conf_t *prev = parent;
    ngx_http_hello_world_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->output_words, prev->output_words, "boy");

    return NGX_CONF_OK;
}

static ngx_http_output_header_filter_pt  ngx_http_next_request_filter;

static ngx_int_t
ngx_http_hello_world_request_filter(ngx_http_request_t *r)
{
    ngx_http_hello_world_ctx_t *ctx;
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hello_world_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->idx = ngx_http_hello_world_idx;
    ngx_http_set_ctx(r, ctx, ngx_http_hello_world_module);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "set hello world context\n");
    return ngx_http_next_request_filter(r);
}

static char *
ngx_http_hello_world(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_world_handler;

    ngx_conf_set_str_slot(cf, cmd, conf);
    ngx_http_next_request_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_hello_world_request_filter;

    return NGX_CONF_OK;
}
