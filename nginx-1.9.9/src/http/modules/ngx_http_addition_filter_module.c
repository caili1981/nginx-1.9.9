
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t     before_body;
    ngx_str_t     after_body;

    ngx_hash_t    types;
    ngx_array_t  *types_keys;
} ngx_http_addition_conf_t;


typedef struct {
    ngx_uint_t    before_body_sent;
} ngx_http_addition_ctx_t;


static void *ngx_http_addition_create_conf(ngx_conf_t *cf);
static char *ngx_http_addition_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_addition_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_addition_commands[] = {

    { ngx_string("add_before_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_addition_conf_t, before_body),
      NULL },

    { ngx_string("add_after_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_addition_conf_t, after_body),
      NULL },

    { ngx_string("addition_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_addition_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_addition_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_addition_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_addition_create_conf,         /* create location configuration */
    ngx_http_addition_merge_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_addition_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_addition_filter_module_ctx,  /* module context */
    ngx_http_addition_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_addition_header_filter(ngx_http_request_t *r)
{
    ngx_http_addition_ctx_t   *ctx;
    ngx_http_addition_conf_t  *conf;

    /*TODO: 重新加上 */
    if (r->headers_out.status != NGX_HTTP_OK /*|| r != r->main*/) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_addition_filter_module);

    if (conf->before_body.len == 0 && conf->after_body.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_test_content_type(r, &conf->types) == NULL) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_addition_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_addition_filter_module);

    /*
     * 暂时无法计算content-length, 响应报文会以chunk方式发送
     * 由于header_filter完成之后，http将会把header送入r->out进行发送，
     * 从流程上看，很多情形下content-length都无法计算出来，只能以chunk方式发送
     */
    ngx_http_clear_content_length(r);

    /*
     * 不支持断点续传
     */
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_addition_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_uint_t                 last;
    ngx_chain_t               *cl;
    ngx_http_request_t        *sr;
    ngx_http_addition_ctx_t   *ctx;
    ngx_http_addition_conf_t  *conf;

    /*
     * 在原始http响应回来时就会进入，不一定会等待所有响应报文都收齐时
     * 才进入，因此，这个filter可能会进入很多次.
     * 因此：
     * 当收到响应报文时就会发送sub-request
     * 当subrequest已经提交时，应该及早退出，并执行下一个body_filter, 
     * 以减少对性能的影响.
     */
    if (in == NULL || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_addition_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_addition_filter_module);

    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1;

        if (conf->before_body.len) {
            /*
             * 此时的subreq作为r->postponed的第一个元素, ngx_http_subrequest会将r->connection->data置为此subreq
             */
            if (ngx_http_subrequest(r, &conf->before_body, NULL, &sr, NULL, 0)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    if (conf->after_body.len == 0) {
        ngx_http_set_ctx(r, NULL, ngx_http_addition_filter_module);
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    /*
     * Next body filter会历经ngx_http_postpone_filter。
     * 那里会判断(如下:)此buffer所对应的请求是不是当前的subrequest的第一个请求.
     *    r->connection->data == r
     * 如果不是第一个请求，则创建一个新的ponstponed_request并加入到队尾
     * 此时postedpone有两个元素:
     *  1. before
     *  2. self
     */
    rc = ngx_http_next_body_filter(r, in);

    /* 如果原请求的最后一个报文仍未接收完成, 则不进行下一个sub-request请求 */
    if (rc == NGX_ERROR || !last || conf->after_body.len == 0) {
        return rc;
    }

    /*
     * 此时postedpone有三个元素:
     *  1. before
     *  2. self
     *  3. after
     */
    if (ngx_http_subrequest(r, &conf->after_body, NULL, &sr, NULL, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, NULL, ngx_http_addition_filter_module);

    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

static ngx_int_t
ngx_http_addition_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_addition_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_addition_body_filter;

    return NGX_OK;
}


static void *
ngx_http_addition_create_conf(ngx_conf_t *cf)
{
    ngx_http_addition_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_addition_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->before_body = { 0, NULL };
     *     conf->after_body = { 0, NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    return conf;
}


static char *
ngx_http_addition_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_addition_conf_t *prev = parent;
    ngx_http_addition_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->before_body, prev->before_body, "");
    ngx_conf_merge_str_value(conf->after_body, prev->after_body, "");

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
