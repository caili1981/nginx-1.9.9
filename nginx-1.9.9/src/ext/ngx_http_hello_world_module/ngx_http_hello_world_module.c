#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
typedef struct {
    ngx_http_complex_value_t *cv;
} ngx_http_hello_world_loc_conf_t;

typedef struct {
    ngx_int_t idx;
    ngx_str_t user_name;
    ngx_str_t footer;
} ngx_http_hello_world_ctx_t;

ngx_int_t ngx_http_hello_world_idx;
static char *ngx_http_hello_world(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_hello_world_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hello_world_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_hello_world_post_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_hello_world_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_hello_world_request_filter(ngx_http_request_t *r);

static ngx_command_t ngx_http_hello_world_commands[] = {
    { ngx_string("hello_world"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_hello_world,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_hello_world_module_ctx = {
    ngx_http_hello_world_add_variables,     
    ngx_http_hello_world_post_conf,     

    NULL,     
    NULL,     

    NULL,     
    NULL,     

    ngx_http_hello_world_create_loc_conf,

    ngx_http_hello_world_merge_loc_conf

};

ngx_int_t ngx_http_hello_world_init_master(ngx_log_t *log)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "init master\n");  
    ngx_http_hello_world_idx = 100000;
    return NGX_OK;
}

ngx_int_t ngx_http_hello_world_init_module(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "init module\n");  
    return NGX_OK;
}

ngx_int_t ngx_http_hello_world_exit_module(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "exit module\n");  
    return NGX_OK;
}

ngx_int_t ngx_http_hello_world_init_thread(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "init thread\n");  
    return NGX_OK;
}

void ngx_http_hello_world_exit_thread(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "exit thread\n");  
    return;
}

ngx_int_t ngx_http_hello_world_init_process(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "init process\n");  
    return NGX_OK;
}

void ngx_http_hello_world_exit_process(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "exit process\n");  
    return;
}

void ngx_http_hello_world_exit_master(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "exit master\n");  
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
ngx_http_hello_world_get_username (ngx_http_request_t *r,
                                   ngx_http_variable_value_t *v,
                                   uintptr_t data)
{
    ngx_http_hello_world_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_world_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can not find context\n");
        return NGX_ERROR;
    }
    v->len = ctx->user_name.len;
    v->valid = 1;
    v->not_found = 0;
    v->data = ctx->user_name.data;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get username to %s\n", (char *)v->data);
    return NGX_OK;
}

void ngx_http_hello_world_set_username (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_hello_world_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_world_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can not find context\n");
        return;
    }

    if (ctx->user_name.data == NULL) {
        ctx->user_name.len = strlen((char *)v->data) + 1;
        ctx->user_name.data = ngx_pcalloc(r->pool, ctx->user_name.len);
        strcpy((char *)ctx->user_name.data, (char *)v->data);
    }

    return;
}
static ngx_http_variable_t  ngx_http_hello_world_vars[] = {

    { ngx_string("user_name"), ngx_http_hello_world_set_username, ngx_http_hello_world_get_username, 0,
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE, 0 }
};

static ngx_int_t
ngx_http_hello_world_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_hello_world_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->set_handler = v->set_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_hello_world_post_read_phase_handler(ngx_http_request_t *r)
{
    ngx_http_hello_world_ctx_t *ctx;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "go to post read phase\n");
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hello_world_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->idx = ngx_http_hello_world_idx++;
    ngx_http_set_ctx(r, ctx, ngx_http_hello_world_module);
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_hello_world_content_phase_handler(ngx_http_request_t *r)
{
#if 0
    ngx_chain_t *out;
    ngx_buf_t *b;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "go to content phase\n");

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (!b) {
        return NGX_ERROR;
    }
    b->pos = (u_char *)"\nAdded by content phase handler\n";
    b->last = b->pos + sizeof("\nAdded by content phase handler\n") - 1;
    out->buf = b;
    out->next = r->out;
    b->memory = 1;
    b->last_buf = 0;
    r->out = out;
    r->headers_out.content_length_n += b->last - b->pos;
#endif

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_hello_world_post_conf(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_hello_world_post_read_phase_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_hello_world_content_phase_handler;
    return NGX_OK;
}

static ngx_int_t
ngx_http_hello_world_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_hello_world_ctx_t *ctx;
    char c_stats[100];
    ngx_buf_t *b;
    ngx_chain_t out[4];

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[0].buf = b;
    out[0].next = &out[1];

    b->pos = (u_char *) "hello_world, ";
    b->last = b->pos + sizeof("hello_world, ") - 1;
    b->memory = 1;
    b->last_buf = 0;

    ngx_http_hello_world_request_filter(r);

    ctx = ngx_http_get_module_ctx(r, ngx_http_hello_world_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can not find context\n");
        return NGX_ERROR;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[1].buf = b;
    out[1].next = &out[2];

    b->pos = ctx->footer.data;
    b->last = ctx->footer.data + (ctx->footer.len);
    b->memory = 1;
    b->last_buf = 0;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    out[2].buf = b;
    out[2].next = &out[3];
    b->pos = (u_char *)"\n";
    b->last = b->pos + 1;
    b->memory = 1;
    b->last_buf = 0;

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
    r->headers_out.content_length_n = ctx->footer.len
        + sizeof("hello_world, ") + strlen(c_stats);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "content length: %d\n", r->headers_out.content_length_n);
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

    conf->cv = NULL;

    return conf;
}

/* Jack: by default replace the parent with child configuration */
static char *
ngx_http_hello_world_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_hello_world_request_filter(ngx_http_request_t *r)
{
    ngx_http_hello_world_ctx_t *ctx;
    ngx_http_hello_world_loc_conf_t *lcf;
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hello_world_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->idx = ngx_http_hello_world_idx;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);
    if (ngx_http_complex_value(r, lcf->cv, &ctx->footer) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_hello_world_module);
    return NGX_OK;
}


static char *
ngx_http_hello_world(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_world_handler;

    ngx_http_set_complex_value_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}
