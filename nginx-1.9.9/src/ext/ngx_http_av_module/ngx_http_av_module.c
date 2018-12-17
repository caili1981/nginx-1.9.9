#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

int av_seq;

typedef struct {
    ngx_flag_t enable;
    ngx_http_complex_value_t *cache_path;
    ngx_http_complex_value_t *msg;
    char *magic;
} ngx_http_av_loc_conf_t;

typedef struct {
    ngx_file_t  file;
    ngx_chain_t *in;
    ngx_chain_t **last;
    int         holding_size;
} ngx_http_av_ctx_t;

static ngx_int_t ngx_http_av_init(ngx_conf_t *cf);
static void * ngx_http_av_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_av_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_av_commands[] = {
    { ngx_string("av"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_av_loc_conf_t, enable),
        NULL,
    },
    { ngx_string("av_cache_path"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_av_loc_conf_t, cache_path),
        NULL,
    },

    { ngx_string("av_msg"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_av_loc_conf_t, msg),
        NULL,
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_av_module_ctx = {
    NULL,
    ngx_http_av_init,     

    NULL,
    NULL,     

    NULL,
    NULL,     

    ngx_http_av_create_loc_conf,
    ngx_http_av_merge_loc_conf,
};

ngx_module_t  ngx_http_av_module = {
    NGX_MODULE_V1,
    &ngx_http_av_module_ctx,               
    ngx_http_av_commands,                  
    NGX_HTTP_MODULE,                                  
    NULL,                                             
    NULL,                                              
    NULL,                                             
    NULL,                                             
    NULL,                                              
    NULL,                                             
    NULL,                                             
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_av_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_uint_t             last = 0;
    ngx_http_av_ctx_t       *ctx;
    ngx_chain_t            *cl;
    ngx_file_t             file;
    ngx_str_t              uri;
    ngx_http_request_t        *sr;

    ctx = ngx_http_get_module_ctx(r, ngx_http_av_module);
    if (!ctx) {
        /* 如果av 没有使能，直接进入下一个body filter */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "av: passed %0x\n", (ngx_uint_t)r);
        return ngx_http_next_body_filter(r, in);
    }

    if (!in) {
        return NGX_OK;
    }

    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
        return NGX_ERROR;
    }

    for (cl = in; cl; cl = cl->next) {
        ctx->holding_size += (in->buf->last - in->buf->start);
        if (cl->buf->last_buf) {
            last = 1;
            break;
        }
    }

    if (!last) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "av: holding buffer, current size:%d\n", ctx->holding_size);  
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "av: write to local file:%d, r = 0x%x\n", file.fd, (ngx_uint_t)r);  
    ngx_write_chain_to_file(&ctx->file, ctx->in, 0, r->pool);
    ngx_close_file(ctx->file.fd);
    ngx_http_set_ctx(r, NULL, ngx_http_av_module);

    /*
     *  todo:  预处理
     *  1.   chunk 模式
     *  2.   gzip文件.
     *  3.   支持mime
     */

    /*
     *  todo: 
     *  av scaning the file
     */

    /*
     *  todo:
     *  1.   如果发现病毒, 进行云查杀
     *  2.   修改响应内容
     *  3.   
     */

    uri.data = (u_char *)"/av_scan_tmp_result";
    uri.len = strlen((char *)uri.data);
    if (ngx_http_subrequest(r, &uri, NULL, &sr, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;


#if 0
    return ngx_http_send_special(r, NGX_HTTP_LAST);
    return ngx_http_next_body_filter(r, ctx->in);
#endif
}

static ngx_int_t
ngx_http_av_header_filter(ngx_http_request_t *r)
{
    ngx_http_av_loc_conf_t *lcf;
    ngx_http_av_ctx_t *ctx;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_av_module);
    if (!lcf || !lcf->enable || lcf->enable == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "av is not enabled\n");  
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_av_ctx_t));
    if (!ctx) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "not enough memory\n");  
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_complex_value(r, lcf->cache_path, &ctx->file.name) != NGX_OK) {
        return NGX_ERROR;
    }
    ctx->file.name.data[ctx->file.name.len] = '\0';

    ctx->file.log = r->connection->log;
#if 0
    ctx->file.fd = ngx_open_file(ctx->file.name.data, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN, 0x777);
#endif
    ctx->file.fd = ngx_open_file(ctx->file.name.data, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN, 0x777);
    av_seq++;
    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "av: failed to open file[%s]:%s\n", ctx->file.name.data, strerror(errno));  
        ngx_http_set_ctx(r, NULL, ngx_http_av_module);
        return NGX_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                   "av: created new file:%s succeed\n", ctx->file.name.data);

    ngx_http_set_ctx(r, ctx, ngx_http_av_module);
    ctx->last = &ctx->in;

    /*
     * 设置chunk mode
     * 不更改content-type
     */
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s:%d set to chunk mode\n", 
                   __FUNCTION__, __LINE__);  
    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);
    return ngx_http_next_header_filter(r);
}

static void *
ngx_http_av_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_av_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_av_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * 一定要初始化成-1, 否则就会报错
     */
    conf->enable = -1;
    conf->magic = "create";
    return conf;
}

static char *
ngx_http_av_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_av_loc_conf_t *prev = parent;
    ngx_http_av_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    if (conf->cache_path == NULL) {
        conf->cache_path =  prev->cache_path;
    }

    if (conf->msg == NULL) {
        conf->msg =  prev->msg;
    }
    conf->magic = "merged";
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_av_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_av_body_filter;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_av_header_filter;

    return NGX_OK;
}
