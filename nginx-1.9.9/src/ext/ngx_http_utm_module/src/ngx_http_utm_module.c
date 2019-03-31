#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

int utm_seq;

typedef struct {
    ngx_flag_t enable;
    ngx_str_t  target_url;
    ngx_http_complex_value_t *cache_path;
    ngx_http_complex_value_t *msg;
    char *magic;
} ngx_http_utm_loc_conf_t;

typedef struct {
    int header_sent;
    int  scaned;
    ngx_file_t  file;
    ngx_chain_t *in;
    ngx_chain_t **last;
    int         holding_size;
} ngx_http_utm_ctx_t;

static void * ngx_http_utm_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_utm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_utm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_utm_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_utm_header_filter(ngx_http_request_t *r);
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
static ngx_int_t ngx_http_utm_init(ngx_conf_t *cf);

static ngx_int_t
ngx_http_utm_get_target_url(ngx_http_request_t *r,
                                   ngx_http_variable_value_t *v,
                                   uintptr_t data)
{
    ngx_int_t key;
    ngx_str_t var = ngx_string("arg_url");
    ngx_str_t orig_url;
    ngx_http_variable_value_t  *vv;
    key = ngx_hash(var.data, var.len);
    ngx_str_t target_url;
    u_char *orig, *target;
    vv = ngx_http_get_variable(r->main, &var, key);
    if (vv == NULL) {
        return NGX_ERROR;
    }

    target_url.len = vv->len;
    target_url.data = vv->data;

    orig_url.data = ngx_pcalloc(r->pool, target_url.len);
    if (!orig_url.data) {
        return NGX_ERROR;
    }
    orig_url.len = 0;
    orig = orig_url.data;
    target = target_url.data;
    ngx_unescape_uri(&orig_url.data, &target_url.data, target_url.len, NGX_UNESCAPE_URI);
    target_url.len -= (target_url.data - target);
    if (target_url.len > 0) {
        *orig_url.data++ = '?';
        ngx_unescape_uri(&orig_url.data, &target_url.data, target_url.len, NGX_UNESCAPE_URI);
    }
#if 0
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "utm: can not decode %v\n", &target_url);
        return NGX_ERROR;
    }
#endif
    orig_url.data = orig;
    target_url.data = target;
    orig_url.len = strlen((char *)orig);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                   "utm: decode %v to %v\n", &target_url, &orig_url);

    v->len = orig_url.len;
    v->valid = 1;
    v->not_found = 0;
    v->data = orig_url.data;
    return NGX_OK;
}

static ngx_http_variable_t  ngx_http_utm_vars[] = {

    { ngx_string("utm_target_url"), NULL, ngx_http_utm_get_target_url, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
ngx_http_utm_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_utm_vars; v->name.len; v++) {
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

static ngx_command_t ngx_http_utm_commands[] = {
    { ngx_string("utm"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_utm,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_utm_loc_conf_t, enable),
        NULL,
    },
    { ngx_string("utm_cache_path"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_utm_loc_conf_t, cache_path),
        NULL,
    },
    { ngx_string("utm_msg"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_utm_loc_conf_t, msg),
        NULL,
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_utm_module_ctx = {
    ngx_http_utm_add_variables,
    ngx_http_utm_init,     

    NULL,
    NULL,     

    NULL,
    NULL,     

    ngx_http_utm_create_loc_conf,
    ngx_http_utm_merge_loc_conf,
};

ngx_module_t  ngx_http_utm_module = {
    NGX_MODULE_V1,
    &ngx_http_utm_module_ctx,               
    ngx_http_utm_commands,                  
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

static ngx_int_t
ngx_http_utm_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_uint_t             last = 0;
    ngx_http_utm_ctx_t     *ctx;
    ngx_chain_t            *cl;
    ngx_str_t              uri;
    ngx_file_t             file;
    ngx_http_request_t        *pr, *sr;
    ngx_uint_t             size = 0;

    pr = r->main;

    /* TODO: 似乎在sub_request里last_buf不会被标记 */
    for (cl = in; cl; cl = cl->next) {
        size += (in->buf->last - in->buf->start);
        if (cl->buf->last_buf) {
            last = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                           "utm: got last buffer for request: 0x%p\n", r);  
            break;
        }
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_utm_module);
    if (!ctx || ctx->scaned) {
        /* 如果utm 没有使能，直接进入下一个body filter */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm: passed %p\n", r);
        return ngx_http_next_body_filter(r, in);
    }

    ctx->holding_size += size;

    if (!in) {
        return NGX_OK;
    }

    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!last) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm: holding buffer, current size:%d\n", ctx->holding_size);  
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm: write to local file:%d, r = 0x%x\n", file.fd, (ngx_uint_t)r);  
    ngx_write_chain_to_file(&ctx->file, ctx->in, 0, r->pool);
    ngx_close_file(ctx->file.fd);
    ctx->scaned = 1;

    /*
     *  todo:  预处理
     *  1.   chunk 模式
     *  2.   gzip文件.
     *  3.   支持mime
     */

    /*
     *  todo: 
     *  utm scaning the file
     */

    /*
     *  todo:
     *  1.   如果发现病毒, 进行云查杀
     *  2.   修改响应内容
     *  3.   
     */

    uri.data = (u_char *)"/utm_scan_tmp_result";
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
ngx_http_utm_header_filter(ngx_http_request_t *r)
{
    ngx_http_utm_ctx_t *ctx;
    ngx_http_request_t *pr;

    pr = r->main;
    ctx = ngx_http_get_module_ctx(pr, ngx_http_utm_module);
    if (!ctx) {
        /* 如果utm 没有使能，直接进入下一个body filter */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm: not configured %0x\n", (ngx_uint_t)r);
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status != NGX_HTTP_OK) {  /* 为什么需要用headers_out, 而不是headers_in???*/
        ngx_http_finalize_request(pr, NGX_HTTP_SERVICE_UNAVAILABLE);
        return NGX_ERROR;
    }

    /*
     * 设置chunk mode
     * 不更改content-type
     */
    return ngx_http_next_header_filter(r);

}

static void *
ngx_http_utm_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_utm_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_utm_loc_conf_t));
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
ngx_http_utm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_utm_loc_conf_t *prev = parent;
    ngx_http_utm_loc_conf_t *conf = child;
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

int
yara_av_scan(char *file, char **virus_info);
/*子请求结束时回调该方法*/
static ngx_int_t 
ngx_http_utm_subrequest_post_handler(ngx_http_request_t*r, void*data, ngx_int_t rc)
{
    ngx_http_request_t        *sr, *pr;
    ngx_str_t              uri;
    ngx_http_utm_ctx_t       *ctx;
    ngx_str_t              virus_info;
    ngx_http_post_subrequest_t *psr;

    pr = r->main;

    if (rc != NGX_HTTP_OK && rc != NGX_OK) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm: subrequest %v failed: %d\n", &r->uri, rc);
        pr->headers_out.status = rc;
        ngx_str_set(&pr->headers_out.content_type, "text/html");
        ngx_http_weak_etag(pr);
        ngx_http_send_header(pr);
        return rc;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_utm_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pr->connection->log, 0, "utm: subrequest %v finished\n", &r->uri);
    if (ctx->scaned == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm: write to file :%d\n", ctx->holding_size);  
        if (ctx->in) {  /* 如果域名解析失败, ctx->in 会为空 */
            ngx_write_chain_to_file(&ctx->file, ctx->in, 0, r->pool); 
        }
        ngx_close_file(ctx->file.fd);
        
        memset(&virus_info, 0, sizeof(ngx_str_t));
        yara_av_scan((char *)ctx->file.name.data, (char **)&virus_info.data);

        ctx->scaned = 1;

        if (virus_info.data == NULL) {
            uri.data = (u_char *)"/clean";
            uri.len = strlen((char *)uri.data);
        } else {
            uri.data = (u_char *)"/virus_found";
            uri.len = strlen((char *)uri.data);
            virus_info.len = strlen((char *)virus_info.data);
        }

        psr = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (psr == NULL) {
            return NGX_ERROR;
        }

        psr->data = NULL;
        psr->handler = ngx_http_utm_subrequest_post_handler;
        if (virus_info.data != NULL) {
            if (ngx_http_subrequest(r, &uri, &virus_info, &sr, psr, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        } else {
            if (ngx_http_subrequest(r, &uri, NULL, &sr, psr, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ctx->header_sent == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pr->connection->log, 0, "utm: sending header out\n");
            pr->headers_out.status = NGX_HTTP_OK;
            ngx_str_set(&pr->headers_out.content_type, "text/html"); /* TODO: set the original content type later */
            ngx_http_clear_content_length(pr);
            ngx_http_clear_accept_ranges(pr);
            ngx_http_weak_etag(pr);
            ngx_http_send_header(pr);
            ctx->header_sent = 1;
        }
    } else {
        /* 
         * flush/last here is to make the flush point, 
         * or the write filter will not set the buffer flag, 
         * as a result, the ngx_http_postpone_filter will not 
         * continue the ngx_http_next_body_filter. In the last,
         * the message is not sent out 
         */
        ngx_http_send_special(pr, NGX_HTTP_LAST);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_utm_handler(ngx_http_request_t *r)
{
    ngx_http_request_t        *sr;
    ngx_str_t              uri, arg;
    ngx_http_post_subrequest_t *psr;
    ngx_http_utm_ctx_t       *ctx;
    ngx_http_utm_loc_conf_t *lcf;
    ngx_http_variable_value_t var;
    ngx_int_t rc;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_utm_ctx_t));
    if (!ctx) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "not enough memory\n");  
        return NGX_ERROR;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_utm_module);
    if (!lcf || !lcf->enable || lcf->enable == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "utm is not enabled\n");  
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
    utm_seq++;
    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "utm: failed to open file[%s]:%s\n", ctx->file.name.data, strerror(errno));  
        ngx_http_set_ctx(r, NULL, ngx_http_utm_module);
        return NGX_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                   "utm: created new file:%s succeed\n", ctx->file.name.data);

    ngx_http_set_ctx(r, ctx, ngx_http_utm_module);
    ctx->last = &ctx->in;

    uri.data = (u_char *)"/utm_orig";
    uri.len = strlen((char *)uri.data);

    psr = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->data = NULL;
    psr->handler = ngx_http_utm_subrequest_post_handler;

    /* 
     * 在这里不能使用in_memory flag, 因为如果缓存的文件过大，subrequest将会出错
     */
    rc = ngx_http_utm_get_target_url(r, &var, 0);
    if (rc != NGX_OK || var.not_found == 1 || var.valid != 1) {
        return NGX_ERROR;
    }
    arg.len = var.len;
    arg.data = var.data;
    if (ngx_http_subrequest(r, &uri, &arg, &sr, psr, 0 /*NGX_HTTP_SUBREQUEST_IN_MEMORY*/) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static char *
ngx_http_utm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_utm_loc_conf_t *lcf;
    ngx_http_core_loc_conf_t *clcf;

    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_utm_module);

    if (lcf->enable) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_utm_handler;
    }

    return NGX_CONF_OK;
}

int yara_av_init(char *pattern_file);
static ngx_int_t
ngx_http_utm_init(ngx_conf_t *cf)
{
    if (yara_av_init("/home/jackcai/rule-repo/rules/index.yar.out") != 0) {
        printf("load yara rule failed\n");
        return NGX_ERROR;
    }
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_utm_body_filter;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_utm_header_filter;

    return NGX_OK;
}
