#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*********************************
 *** Nginx core resolver notes ***
 *********************************
 * 1 cache record takes ~ 150bytes.
 * Cache maximum expired time is always 30s.
 * Cache minimum expired time taken from:
 *   1. valid, if valid resolver option set;
 *   2. ttl from dns answer.
 * Cache cleared by 2 records in the end of every query.
 * 300,000 queries from different ip's in 30s take ~50Mb cache.
 * Every process have own cache.
 */


#if (NGX_DEBUG)

#include <stdio.h>

#define debug(...) { fprintf(stderr, "nginx: [debug] rdns: "); \
                     fprintf(stderr, __VA_ARGS__); \
                     fprintf(stderr, "\n"); }

#define debug_code(...) { __VA_ARGS__; }

#else
#define debug(...)
#define debug_code(...)
#endif


#ifndef NGX_RDNS_NO_IF

extern ngx_module_t ngx_http_rewrite_module;


typedef struct {
    ngx_http_script_code_pt code;
    ngx_flag_t enabled;
} ngx_http_rdns_enable_code_t;


static void enable_code(ngx_http_script_engine_t * e);

#endif


static const ngx_str_t var_rdns_result_name = ngx_string("rdns_hostname");
static const ngx_str_t var_rdns_result_uninitialized = ngx_string("-");
static const ngx_str_t var_rdns_result_not_found = ngx_string("not found");


typedef enum {
    NGX_HTTP_RDNS_CTX_ENABLE,
    NGX_HTTP_RDNS_CONF_ENABLE
} enable_source_t;


typedef struct {
    ngx_int_t rdns_result_index;
    ngx_flag_t enabled;
} ngx_http_rdns_loc_conf_t;


typedef struct {
    ngx_flag_t resolved;
    enable_source_t enable_source;
    ngx_flag_t enabled;
} ngx_http_rdns_ctx_t;


static ngx_int_t preconfig(ngx_conf_t * cf);
static ngx_int_t postconfig(ngx_conf_t * cf);
static void *    create_loc_conf(ngx_conf_t * cf);
static char *    merge_loc_conf(ngx_conf_t * cf, void * parent, void * child);
static char *    rdns_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static ngx_int_t phase_handler(ngx_http_request_t * r);
static void      rdns_handler(ngx_resolver_ctx_t * ctx);
static ngx_int_t var_rdns_result_getter(ngx_http_request_t * r, ngx_http_variable_value_t * v, uintptr_t data);
static ngx_http_rdns_ctx_t * create_context(ngx_http_request_t * r);


static ngx_command_t  ngx_http_rdns_commands[] = {

    { ngx_string("rdns"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG
#ifndef NGX_RDNS_NO_IF
      | NGX_HTTP_LIF_CONF | NGX_HTTP_SIF_CONF
#endif
      ,
      rdns_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_rdns_module_ctx = {
    preconfig,         /* preconfiguration */
    postconfig,        /* postconfiguration */

    NULL,              /* create main configuration */
    NULL,              /* init main configuration */

    NULL,              /* create server configuration */
    NULL,              /* merge server configuration */

    create_loc_conf,   /* create location configuration */
    merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_rdns_module = {
    NGX_MODULE_V1,
    &ngx_http_rdns_module_ctx, /* module context */
    ngx_http_rdns_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};


static void * create_loc_conf(ngx_conf_t * cf) {
    ngx_http_rdns_loc_conf_t * conf;

    debug("creating location conf");

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_rdns_loc_conf_t));
    if (conf != NULL) {
        conf->enabled = NGX_CONF_UNSET;
        conf->rdns_result_index = NGX_CONF_UNSET;
    }

    debug_code(
            char filename_buf[cf->conf_file->file.name.len + 1];
            memcpy(filename_buf, cf->conf_file->file.name.data, cf->conf_file->file.name.len);
            filename_buf[cf->conf_file->file.name.len] = '\0';

            debug("(DONE) creating location conf = %p in %s:%lu",
                    conf, filename_buf, cf->conf_file->line);
    );

    return conf;
}


static char * merge_loc_conf(ngx_conf_t * cf, void * parent, void * child) {
    ngx_http_rdns_loc_conf_t * prev = parent;
    ngx_http_rdns_loc_conf_t * conf = child;
    ngx_http_core_loc_conf_t * core_loc_cf;

    debug("merging location configs: %p -> %p", prev, conf);

    core_loc_cf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_value(conf->rdns_result_index, prev->rdns_result_index,
            ngx_http_get_variable_index(cf, (ngx_str_t *)&var_rdns_result_name));

    if (conf->enabled && ((core_loc_cf->resolver == NULL) || (core_loc_cf->resolver->udp_connections.nelts == 0))) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no core resolver defined for rdns");
        return NGX_CONF_ERROR;
    }

    debug("(DONE) merging location configs");

    return NGX_CONF_OK;
}


static ngx_int_t preconfig(ngx_conf_t * cf) {
    ngx_http_variable_t * var;

    debug("preconfig");

    var = ngx_http_add_variable(cf, (ngx_str_t *)&var_rdns_result_name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = var_rdns_result_getter;

    debug("(DONE) preconfig");

    return NGX_OK;
}


static ngx_int_t postconfig(ngx_conf_t * cf) {
    ngx_http_core_main_conf_t * core_main_cf;
    ngx_http_handler_pt * h;
    ngx_array_t * arr;
    int i;

    debug("postconfig");

    core_main_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    arr = &core_main_cf->phases[NGX_HTTP_REWRITE_PHASE].handlers;
    h = ngx_array_push(arr);
    if (h == NULL) {
        debug("unable to setup phase handler")
        return NGX_ERROR;
    }

    /* Enable code running on REWRITE phase.
     * Enable code should run before rdns phase_handler.
     * So we add phase_handler as last handler in REWRITE phase.
     */
    for (i = arr->nelts - 1; i > 0; --i) {
        *((ngx_http_handler_pt *)arr->elts + i) = *((ngx_http_handler_pt *)arr->elts + i - 1);
    }
    *(ngx_http_handler_pt *)arr->elts = phase_handler;

    debug("(DONE) postconfig");

    return NGX_OK;
}


/*
 * Module enable directive. Directive may be in any context.
 * In main, server and location contexts it statically enables module.
 * In 'server if' and 'location if' contexts module works through rewrite module codes
 *     by adding own code ngx_http_rdns_enable_code_t.
 */
static char * rdns_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
    ngx_http_rdns_loc_conf_t * loc_conf = conf;
    ngx_str_t * value;
    ngx_flag_t enabled = 0;

    debug("rdns directive");

    if (loc_conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
        debug("location config NULL pointer");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    if (ngx_strcasecmp(value[1].data, (u_char *)"on") == 0) {
        enabled = 1;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"off") == 0) {
        enabled = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

#ifndef NGX_RDNS_NO_IF
    if (cf->cmd_type & (NGX_HTTP_LIF_CONF | NGX_HTTP_SIF_CONF)) {
        ngx_http_rdns_enable_code_t * code;
        void * rewrite_lcf;

        /*
         * Enable code used to determine enabled state in runtime (when processing request).
         * Enable code should run only if directive used inside 'if'.
         */

        debug("setup enable code");
        rewrite_lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_rewrite_module);
        if (rewrite_lcf == NULL) {
            debug("unable to get rewrite location config");
            return NGX_CONF_ERROR;
        }

        code = ngx_http_script_start_code(cf->pool, (ngx_array_t **)rewrite_lcf,
                                               sizeof(ngx_http_rdns_enable_code_t));
        if (code == NULL) {
            debug("unable to add enable code to rewrite module");
            return NGX_CONF_ERROR;
        }

        code->code = enable_code;
        code->enabled = enabled;
        loc_conf->enabled = enabled;
    } else {
        /* statically enable module otherwise */
#endif
        loc_conf->enabled = enabled;
#ifndef NGX_RDNS_NO_IF
    }
#endif

    debug("(DONE) rdns directive: enabled = %lu", enabled);

    return NGX_CONF_OK;
}


/*
 * Module check enabled state as follows:
 *  1. Check existence of request context.
 *  2. If exists take enable from 'enable source',
 *      take enabled from location config otherwise.
 */
static ngx_int_t phase_handler(ngx_http_request_t * r) {
    ngx_http_rdns_loc_conf_t * loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_rdns_module);
    ngx_http_core_loc_conf_t * core_loc_cf;
    ngx_resolver_ctx_t * rctx;
    ngx_http_rdns_ctx_t * ctx = ngx_http_get_module_ctx(r, ngx_http_rdns_module);
    struct sockaddr_in * sin;
    ngx_flag_t enabled = 0;

    if (loc_cf == NULL) {
        /* isn't possible, but who knows... */
        return NGX_DECLINED;
    }

    if (ctx == NULL) {
        enabled = loc_cf->enabled;
    } else if (ctx->enable_source == NGX_HTTP_RDNS_CONF_ENABLE) {
        enabled = loc_cf->enabled;
    } else if (ctx->enable_source == NGX_HTTP_RDNS_CTX_ENABLE) {
        enabled = ctx->enabled;
    }

    if (enabled) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns handler");

        if ((ctx != NULL) && ctx->resolved) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns handler: already resolved");
            return NGX_DECLINED;
        } else if (ctx == NULL) {
            /* Context needed because of ctx->resolved flag */
            ctx = create_context(r);
            if (ctx == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "rdns handler: unable to create request context");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ctx->enable_source = NGX_HTTP_RDNS_CONF_ENABLE;
            ctx->resolved = 0;
        }

        if (loc_cf == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns handler: failed to get rdns main config");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        core_loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        if (core_loc_cf == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns handler: failed to get core location config");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rctx = ngx_resolve_start(core_loc_cf->resolver, NULL);
        if (rctx == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns handler: unable to create resolver context");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rctx == NGX_NO_RESOLVER) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns handler: core resolver is not defined");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        sin = (struct sockaddr_in *) r->connection->sockaddr;
        rctx->addr = sin->sin_addr.s_addr;
        rctx->type = NGX_RESOLVE_PTR;
        rctx->handler = rdns_handler;
        rctx->data = r;
        rctx->timeout = core_loc_cf->resolver_timeout;

        if (ngx_resolve_addr(rctx) != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns handler: failed to make rdns request");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns handler [DONE]");
        return NGX_DONE;
    } else {
        return NGX_DECLINED;
    }
}


static void rdns_handler(ngx_resolver_ctx_t * rctx) {
    ngx_http_request_t * r = rctx->data;
    ngx_http_rdns_ctx_t * ctx = ngx_http_get_module_ctx(r, ngx_http_rdns_module);
    ngx_http_rdns_loc_conf_t * loc_cf;
    ngx_http_variable_value_t * rdns_result_val;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rdns dns request handler");

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns handler: failed to get request context");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_rdns_module);
    if (loc_cf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns handler: failed to get rdns main config");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rdns_result_val = r->variables + loc_cf->rdns_result_index;
    if (rdns_result_val == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns handler: bad rdns_result variable");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rctx->state) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns rdns handler: failed with error '%s'",
                ngx_resolver_strerror(rctx->state));

        rdns_result_val->data = var_rdns_result_not_found.data;
        rdns_result_val->len = var_rdns_result_not_found.len;
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns rdns handler: result='%V'",
                &rctx->name);

        rdns_result_val->data = ngx_palloc(r->pool, rctx->name.len * sizeof(u_char));
        ngx_memcpy(rdns_result_val->data, rctx->name.data, rctx->name.len);
        rdns_result_val->len = rctx->name.len;
    }

    rdns_result_val->valid = 1;
    rdns_result_val->not_found = 0;

    ctx->resolved = 1;
    ngx_resolve_addr_done(rctx);

    /*
     * Reset request handling pipeline to make new variable 'rdns_result'
     *  visible by other rewrite phase modules
     */
    r->phase_handler = 1;

    ngx_http_finalize_request(r, NGX_DECLINED);
}


static ngx_int_t var_rdns_result_getter(ngx_http_request_t * r,
        ngx_http_variable_value_t * v, uintptr_t data) {

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = var_rdns_result_uninitialized.len;
    v->data = var_rdns_result_uninitialized.data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rdns '%V' variable getter, value = '%V'",
            &var_rdns_result_name, &var_rdns_result_uninitialized);

    return NGX_OK;
}


static ngx_http_rdns_ctx_t * create_context(ngx_http_request_t * r) {
    ngx_http_rdns_ctx_t * res_ctx = NULL;

    if (r != NULL) {
        res_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rdns_ctx_t));
        ngx_http_set_ctx(r, res_ctx, ngx_http_rdns_module);
    }

    return res_ctx;
}


#ifndef NGX_RDNS_NO_IF

static void enable_code(ngx_http_script_engine_t * e) {
    ngx_http_rdns_ctx_t * ctx = ngx_http_get_module_ctx(e->request, ngx_http_rdns_module);
    ngx_http_rdns_enable_code_t * code = (ngx_http_rdns_enable_code_t *)e->ip;

    if (ctx == NULL) {
        ctx = create_context(e->request);
    }

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                "rdns enable code: unable to get request context");
        return;
    }

    if (!ctx->resolved) {
        ctx->enabled = code->enabled;
        ctx->enable_source = NGX_HTTP_RDNS_CTX_ENABLE;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                "rdns enable code, enabled = %d", ctx->enabled);

        if (ctx->enabled) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                    "rdns enable code, breaking codes");

            ngx_http_script_break_code(e);
            return;
        }
    }

    e->ip += sizeof(ngx_http_rdns_enable_code_t);
}

#endif
