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


typedef struct {
    ngx_flag_t enabled;
    ngx_flag_t double_mode;
} ngx_http_rdns_common_conf_t;


#ifndef NGX_RDNS_NO_IF

extern ngx_module_t ngx_http_rewrite_module;


typedef struct {
    ngx_http_script_code_pt code;
    ngx_http_rdns_common_conf_t conf;
} ngx_http_rdns_enable_code_t;


static void enable_code(ngx_http_script_engine_t * e);

#endif


static const ngx_str_t var_rdns_result_name = ngx_string("rdns_hostname");
static const ngx_str_t var_rdns_result_uninitialized = ngx_string("-");
static const ngx_str_t var_rdns_result_not_found = ngx_string("not found");


#if (NGX_PCRE)

typedef struct {
    ngx_http_regex_t * domain_regex;
    ngx_str_t domain;

    enum {
        NGX_HTTP_RDNS_RULE_ALLOW,
        NGX_HTTP_RDNS_RULE_DENY
    } access_type;
} ngx_http_rdns_rule_t;


static char *     rdns_allow_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static char *     rdns_deny_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static char *     rdns_conf_rule(ngx_conf_t * cf, ngx_command_t * cmd, void * conf, int access_type);
static ngx_int_t  access_handler(ngx_http_request_t * r);
static ngx_flag_t rule_is_match(ngx_http_request_t * r, ngx_http_rdns_rule_t * rule, ngx_str_t * domain);

#endif


typedef struct {
    ngx_int_t rdns_result_index;
    ngx_http_rdns_common_conf_t conf;

#if (NGX_PCRE)
    ngx_array_t * rules;
#endif

} ngx_http_rdns_loc_conf_t;


typedef struct {
    ngx_flag_t resolved;
    ngx_http_rdns_common_conf_t conf;
    enum {
        NGX_HTTP_RDNS_CONF_CTX,
        NGX_HTTP_RDNS_CONF_CONF
    } conf_source;
} ngx_http_rdns_ctx_t;


static ngx_int_t preconfig(ngx_conf_t * cf);
static ngx_int_t postconfig(ngx_conf_t * cf);
static void *    create_loc_conf(ngx_conf_t * cf);
static char *    merge_loc_conf(ngx_conf_t * cf, void * parent, void * child);
static char *    rdns_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf);
static ngx_int_t resolver_handler(ngx_http_request_t * r);
static void      rdns_handler(ngx_resolver_ctx_t * ctx);
static void      resolver_handler_finalize(ngx_http_request_t * r, ngx_http_rdns_ctx_t * ctx);
static void      dns_request(ngx_http_request_t * r, ngx_str_t hostname);
static void      dns_handler(ngx_resolver_ctx_t * ctx);
static ngx_int_t var_rdns_result_getter(ngx_http_request_t * r, ngx_http_variable_value_t * v, uintptr_t data);
static ngx_int_t var_set(ngx_http_request_t * r, ngx_int_t index, ngx_str_t value);
static ngx_http_rdns_ctx_t *         create_context(ngx_http_request_t * r);
static ngx_http_rdns_common_conf_t * rdns_get_common_conf(ngx_http_rdns_ctx_t * ctx, ngx_http_rdns_loc_conf_t * loc_cf);


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

#if (NGX_PCRE)
    { ngx_string("rdns_allow"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      rdns_allow_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("rdns_deny"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      rdns_deny_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
#endif

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
    &ngx_http_rdns_module_ctx,        /* module context */
    ngx_http_rdns_commands,           /* module directives */
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
        conf->conf.enabled = NGX_CONF_UNSET;
        conf->conf.double_mode = NGX_CONF_UNSET;
        conf->rdns_result_index = NGX_CONF_UNSET;
    }

    debug_code(
            char filename_buf[cf->conf_file->file.name.len + 1];
            ngx_memcpy(filename_buf, cf->conf_file->file.name.data, cf->conf_file->file.name.len);
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

    ngx_conf_merge_value(conf->conf.enabled, prev->conf.enabled, 0);
    ngx_conf_merge_value(conf->conf.double_mode, prev->conf.double_mode, 0);
    ngx_conf_merge_value(conf->rdns_result_index, prev->rdns_result_index,
            ngx_http_get_variable_index(cf, (ngx_str_t *)&var_rdns_result_name));

#if (NGX_PCRE)
    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }
#endif

    if (conf->conf.enabled && ((core_loc_cf->resolver == NULL) || (core_loc_cf->resolver->udp_connections.nelts == 0))) {
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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
        debug("unable to setup rewrite phase resolver handler");
        return NGX_ERROR;
    }

    /* Enable code running on REWRITE phase.
     * Enable code should run before rdns phase_handler.
     * So we add phase_handler as last handler in REWRITE phase.
     */
    for (i = arr->nelts - 1; i > 0; --i) {
        *((ngx_http_handler_pt *)arr->elts + i) = *((ngx_http_handler_pt *)arr->elts + i - 1);
    }
    *(ngx_http_handler_pt *)arr->elts = resolver_handler;

#if (NGX_PCRE)
    arr = &core_main_cf->phases[NGX_HTTP_ACCESS_PHASE].handlers;
    h = ngx_array_push(arr);
    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
        debug("unable to setup access phase handler");
        return NGX_ERROR;
    }
    *h = access_handler;
#endif

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
    ngx_http_rdns_common_conf_t cconf;

    debug("rdns directive");

    if (loc_conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
        debug("location config NULL pointer");
        return NGX_CONF_ERROR;
    }

    cconf.enabled = 0;
    cconf.double_mode = 0;

    value = cf->args->elts;
    if (ngx_strcasecmp(value[1].data, (u_char *)"on") == 0) {
        cconf.enabled = 1;
        cconf.double_mode = 0;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"off") == 0) {
        cconf.enabled = 0;
        cconf.double_mode = 0;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"double") == 0) {
        cconf.enabled = 1;
        cconf.double_mode = 1;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\" or \"double\"",
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
        code->conf = cconf;
        loc_conf->conf = cconf;
    } else {
        /* statically enable module otherwise */
#endif
        loc_conf->conf = cconf;
#ifndef NGX_RDNS_NO_IF
    }
#endif

    debug("(DONE) rdns directive: enabled = %lu, double_mode = %lu", cconf.enabled, cconf.double_mode);

    return NGX_CONF_OK;
}


#if (NGX_PCRE)

static char * rdns_conf_rule(ngx_conf_t * cf, ngx_command_t * cmd, void * conf, int access_type) {
    ngx_http_rdns_loc_conf_t * loc_conf = conf;
    ngx_str_t * value;
    ngx_http_rdns_rule_t * rule;
    ngx_regex_compile_t rc;
    u_char errstr[NGX_MAX_CONF_ERRSTR];

    if (loc_conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
        debug("location config NULL pointer");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    if (loc_conf->rules == NULL) {
        loc_conf->rules = ngx_array_create(cf->pool, 1, sizeof(ngx_http_rdns_rule_t));
        if (loc_conf->rules == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
            debug("unable to allocate memory for rules array");
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(loc_conf->rules);
    if (rule == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "internal error");
        debug("unable to allocate memory for rule");
        return NGX_CONF_ERROR;
    }

    rule->access_type = access_type;
    rule->domain = value[1];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = rule->domain;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.options = NGX_REGEX_CASELESS;

    rule->domain_regex = ngx_http_regex_compile(cf, &rc);
    if (rule->domain_regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unable to compile rule regex");
        return NGX_CONF_ERROR;
    }

    debug_code(
        char domain_buf[rule->domain.len + 1];
        ngx_memcpy(domain_buf, rule->domain.data, rule->domain.len);
        domain_buf[rule->domain.len] = '\0';
        debug("rule for domain '%s'", domain_buf);
    );

    return NGX_CONF_OK;
}


static char * rdns_allow_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
    char * res;

    debug("rdns allow directive");
    res = rdns_conf_rule(cf, cmd, conf, NGX_HTTP_RDNS_RULE_ALLOW);
    debug("(DONE) rdns allow directive");

    return res;
}


static char * rdns_deny_directive(ngx_conf_t * cf, ngx_command_t * cmd, void * conf) {
    char * res;

    debug("rdns deny directive");
    res = rdns_conf_rule(cf, cmd, conf, NGX_HTTP_RDNS_RULE_DENY);
    debug("(DONE) rdns deny directive");

    return res;
}

#endif


static ngx_int_t resolver_handler(ngx_http_request_t * r) {
    ngx_http_rdns_loc_conf_t * loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_rdns_module);
    ngx_http_core_loc_conf_t * core_loc_cf;
    ngx_resolver_ctx_t * rctx;
    ngx_http_rdns_ctx_t * ctx = ngx_http_get_module_ctx(r, ngx_http_rdns_module);
    struct sockaddr_in * sin;
    ngx_http_rdns_common_conf_t * cconf;

    if (loc_cf == NULL) {
        /* isn't possible, but who knows... */
        return NGX_DECLINED;
    }

    cconf = rdns_get_common_conf(ctx, loc_cf);
    if (cconf == NULL) {
        return NGX_DECLINED;
    }

    if (cconf->enabled) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: resolver handler");

        if ((ctx != NULL) && ctx->resolved) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: resolver handler: already resolved");
            return NGX_DECLINED;
        } else if (ctx == NULL) {
            /* Context needed because of ctx->resolved flag */
            ctx = create_context(r);
            if (ctx == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "rdns: resolver handler: unable to create request context");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ctx->conf_source = NGX_HTTP_RDNS_CONF_CONF;
            ctx->resolved = 0;
        }

        if (loc_cf == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: resolver handler: failed to get rdns location config");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        core_loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        if (core_loc_cf == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: resolver handler: failed to get core location config");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rctx = ngx_resolve_start(core_loc_cf->resolver, NULL);
        if (rctx == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: resolver handler: unable to create resolver context");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rctx == NGX_NO_RESOLVER) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: resolver handler: core resolver is not defined");
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
                    "rdns: resolver handler: failed to make rdns request");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "(DONE) rdns: resolver handler");
        return NGX_DONE;
    } else {
        return NGX_DECLINED;
    }
}


#if (NGX_PCRE)

static ngx_int_t access_handler(ngx_http_request_t * r) {
    ngx_http_rdns_loc_conf_t * loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_rdns_module);
    ngx_http_rdns_ctx_t * ctx = ngx_http_get_module_ctx(r, ngx_http_rdns_module);
    ngx_http_rdns_common_conf_t * cconf;

    if (loc_cf == NULL) {
        /* isn't possible, but who knows... */
        return NGX_OK;
    }

    cconf = rdns_get_common_conf(ctx, loc_cf);
    if (cconf == NULL) {
        return NGX_OK;
    }

    if (cconf->enabled) {
        ngx_uint_t i;
        ngx_http_rdns_rule_t * rules;
        ngx_http_variable_value_t * rdns_result_val = r->variables + loc_cf->rdns_result_index;
        ngx_str_t rdns_result;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: access handler");

        if (loc_cf->rules != NULL) {
            rdns_result.data = rdns_result_val->data;
            rdns_result.len = rdns_result_val->len;
            rules = loc_cf->rules->elts;

            for (i = 0; i < loc_cf->rules->nelts; ++i) {
                if (rule_is_match(r, rules + i, &rdns_result)) {
                    if (rules[i].access_type == NGX_HTTP_RDNS_RULE_ALLOW) {
                        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "rdns: access handler: access allowed");
                        return NGX_OK;
                    } else {
                        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "rdns: access handler: access denied");
                        return NGX_HTTP_FORBIDDEN;
                    }
                }
            }
        }

    } else {
        return NGX_OK;
    }

    return NGX_OK;
}

#endif


static void rdns_handler(ngx_resolver_ctx_t * rctx) {
    ngx_http_request_t * r = rctx->data;
    ngx_http_rdns_ctx_t * ctx = ngx_http_get_module_ctx(r, ngx_http_rdns_module);
    ngx_http_rdns_loc_conf_t * loc_cf;
    ngx_http_rdns_common_conf_t * cconf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rdns: reverse dns request handler");

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: reverse dns request handler: failed to get request context");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_rdns_module);
    if (loc_cf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: reverse dns request handler: failed to get rdns location config");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rctx->state) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: reverse dns request handler: failed with error '%s'",
                ngx_resolver_strerror(rctx->state));

        ngx_resolve_addr_done(rctx);
        var_set(r, loc_cf->rdns_result_index, var_rdns_result_not_found);
        resolver_handler_finalize(r, ctx);
    } else {
        ngx_str_t hostname;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: reverse dns request handler: result='%V'",
                &rctx->name);

        hostname.data = ngx_palloc(r->pool, rctx->name.len * sizeof(u_char));
        ngx_memcpy(hostname.data, rctx->name.data, rctx->name.len);
        hostname.len = rctx->name.len;

        ngx_resolve_addr_done(rctx);

        cconf = rdns_get_common_conf(ctx, loc_cf);
        if (cconf == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: reverse dns request handler: failed to get common config");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (cconf->double_mode) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: reverse dns request handler: double mode");

            dns_request(r, hostname);
        } else {
            var_set(r, loc_cf->rdns_result_index, hostname);
            resolver_handler_finalize(r, ctx);

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "(DONE) rdns: reverse dns request handler");
        }
    }
}


static void dns_request(ngx_http_request_t * r, ngx_str_t hostname) {
    ngx_resolver_ctx_t * rctx;
    ngx_http_core_loc_conf_t * core_loc_cf;

    if (r == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rdns: dns request");

    core_loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (core_loc_cf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rnds: dns request: failed to get core location config");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rctx = ngx_resolve_start(core_loc_cf->resolver, NULL);
    if (rctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request: unable to create resolver context");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rctx == NGX_NO_RESOLVER) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request: core resolver is not defined");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rctx->name = hostname;
    rctx->type = NGX_RESOLVE_A;
    rctx->handler = dns_handler;
    rctx->data = r;
    rctx->timeout = core_loc_cf->resolver_timeout;

    if (ngx_resolve_addr(rctx) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request: failed to make rdns request");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "(DONE) rdns: dns request");
}


static void dns_handler(ngx_resolver_ctx_t * rctx) {;
    ngx_http_request_t * r = rctx->data;
    ngx_http_rdns_ctx_t * ctx;
    ngx_http_rdns_loc_conf_t * loc_cf;
    struct sockaddr_in * sin;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "rdns: dns request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_rdns_module);
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request handler: failed to get request context");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_rdns_module);
    if (loc_cf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request handler: failed to get rdns location config");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rctx->state) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request handler: failed with error '%s'",
                ngx_resolver_strerror(rctx->state));

        ngx_resolve_name_done(rctx);
        var_set(r, loc_cf->rdns_result_index, var_rdns_result_not_found);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns: dns request handler: result = '%d'", rctx->addr);

        sin = (struct sockaddr_in *) r->connection->sockaddr;
        if (rctx->addr != sin->sin_addr.s_addr) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "rdns: dns request handler: resolving inconsistency: '%d' -> '%V' -> '%d'",
                    sin->sin_addr.s_addr, &rctx->name, rctx->addr);

            ngx_resolve_name_done(rctx);
            var_set(r, loc_cf->rdns_result_index, var_rdns_result_not_found);
        } else {
            var_set(r, loc_cf->rdns_result_index, rctx->name);
            ngx_resolve_name_done(rctx);
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "(DONE) rdns: dns request handler");

    resolver_handler_finalize(r, ctx);
}


static void resolver_handler_finalize(ngx_http_request_t * r, ngx_http_rdns_ctx_t * ctx) {
    if (r == NULL || ctx == NULL) {
        return;
    }

    ctx->resolved = 1;

    /*
     * Reset request handling pipeline to make new variable 'rdns_result'
     *  visible by other rewrite phase modules
     */
    r->uri_changed = 1;

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


static ngx_int_t var_set(ngx_http_request_t * r, ngx_int_t index, ngx_str_t value) {
    ngx_http_variable_value_t * val;

    if (r == NULL) {
        return 1;
    }

    val = r->variables + index;
    if (val == NULL) {
        return 1;
    }

    val->data = value.data;
    val->len = value.len;
    val->valid = 1;
    val->not_found = 0;

    return 0;
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
        ctx->conf = code->conf;
        ctx->conf_source = NGX_HTTP_RDNS_CONF_CTX;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                "rdns enable code, enabled = %d, double mode = %d", ctx->conf.enabled, ctx->conf.double_mode);

        if (ctx->conf.enabled) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                    "rdns enable code, breaking codes");

            ngx_http_script_break_code(e);
            return;
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                "rdns enable code: already resolved");
    }

    e->ip += sizeof(ngx_http_rdns_enable_code_t);
}

#endif


/*
 * Module check enabled state as follows:
 *  1. Check existence of request context.
 *  2. If exists take enable from 'conf source',
 *      take enable from location config otherwise.
 */
static ngx_http_rdns_common_conf_t * rdns_get_common_conf(ngx_http_rdns_ctx_t * ctx, ngx_http_rdns_loc_conf_t * loc_cf) {
    if (loc_cf == NULL) {
        return NULL;
    } else if (ctx == NULL) {
        return &loc_cf->conf;
    } else if (ctx->conf_source == NGX_HTTP_RDNS_CONF_CONF) {
        return &loc_cf->conf;
    } else if (ctx->conf_source == NGX_HTTP_RDNS_CONF_CTX) {
        return &ctx->conf;
    } else {
        return NULL;
    }
}


#if (NGX_PCRE)

static ngx_flag_t rule_is_match(ngx_http_request_t * r, ngx_http_rdns_rule_t * rule, ngx_str_t * domain) {
    ngx_flag_t res;

    if (rule == NULL || domain == NULL) {
        return 0;
    }

    res = (ngx_http_regex_exec(r, rule->domain_regex, domain) == NGX_OK);
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "rdns check rule regex '%V' with '%V': %s", &rule->domain, domain,
                (res == 1 ? "matched" : "not matched"));

    return res;
}

#endif
