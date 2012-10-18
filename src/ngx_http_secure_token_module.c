/*
 * Copyright (c) 2012, NetDNA LLC. <contact@netdna.com>
 * Copyright (c) 2012, FRiCKLE <info@frickle.com>
 * Copyright (c) 2012, Piotr Sikora <piotr.sikora@frickle.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_flag_t                 enable;
    ngx_str_t                  key;
    ngx_array_t               *md5;
    ngx_http_complex_value_t  *input;
    u_char                     input_sep;
} ngx_http_secure_token_loc_conf_t;


typedef struct {
    ngx_str_t                  input;
    time_t                     expire_time;
    ngx_str_t                  expire_str;
    ngx_str_t                  token;
    ngx_str_t                  access;
    u_char                     md5[16];
} ngx_http_secure_token_ctx_t;


typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  input[3];
    ngx_str_t                  md5[3];
} ngx_http_secure_token_enum_t;


static ngx_int_t ngx_http_secure_token_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_secure_token_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_secure_token_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_secure_token_parse_input(ngx_http_request_t *r);
static ngx_int_t ngx_http_secure_token_variable_key(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_md5(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_input(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_input_expire(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_input_expire_native(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_input_expire_32bit(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_input_token(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_input_access(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_unparsed_uri(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_token_variable_lowercase_uri(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_secure_token_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_secure_token_conf_md5(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_secure_token_conf_input(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_secure_token_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_secure_token_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t ngx_http_secure_token_module_commands[] = {

    { ngx_string("secure_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_secure_token_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_token_loc_conf_t, enable),
      NULL },

    { ngx_string("secure_token_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_token_loc_conf_t, key),
      NULL },

    { ngx_string("secure_token_md5"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_secure_token_conf_md5,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_token_loc_conf_t, md5),
      NULL },

    { ngx_string("secure_token_input"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_secure_token_conf_input,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_token_loc_conf_t, input),
      NULL },

      ngx_null_command
};


static ngx_http_variable_t ngx_http_secure_token_module_variables[] = {

    { ngx_string("secure_token_key"), NULL,
      ngx_http_secure_token_variable_key, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_md5"), NULL,
      ngx_http_secure_token_variable_md5, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_input"), NULL,
      ngx_http_secure_token_variable_input, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_input_expire"), NULL,
      ngx_http_secure_token_variable_input_expire, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_input_expire_native"), NULL,
      ngx_http_secure_token_variable_input_expire_native, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_input_expire_32bit"), NULL,
      ngx_http_secure_token_variable_input_expire_32bit, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_input_token"), NULL,
      ngx_http_secure_token_variable_input_token, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("secure_token_input_access"), NULL,
      ngx_http_secure_token_variable_input_access, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("unparsed_uri"), NULL,
      ngx_http_secure_token_variable_unparsed_uri, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("lowercase_uri"), NULL,
      ngx_http_secure_token_variable_lowercase_uri, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_module_t ngx_http_secure_token_module_ctx = {
    ngx_http_secure_token_add_variables,    /* preconfiguration */
    ngx_http_secure_token_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_secure_token_create_loc_conf,  /* create location configuration */
    ngx_http_secure_token_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_secure_token_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_token_module_ctx,      /* module context */
    ngx_http_secure_token_module_commands,  /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_secure_token_enum_t ngx_http_secure_token_values[] = {
    { ngx_string("on"),
      { ngx_null_string, ngx_null_string },
      { ngx_null_string, ngx_null_string } },

    { ngx_string("example1"), 
      { ngx_string("$arg_example1dlm"),  /* input value */
        ngx_null_string },             /* input separator */
      { ngx_string("${secure_token_input_expire_32bit}${unparsed_uri}${secure_token_key}"),
        ngx_string("${secure_token_key}${secure_token_md5}") } },

    { ngx_string("example2"), 
      { ngx_string("$cookie_SIPDownloadAuth"),  /* input value */
        ngx_string("~") },                      /* input separator */
      { ngx_string("${secure_token_input_expire}${secure_token_input_access}${secure_token_key}"),
        ngx_null_string } },

    { ngx_null_string,
      { ngx_null_string, ngx_null_string },
      { ngx_null_string, ngx_null_string } }
};


static ngx_int_t
ngx_http_secure_token_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_secure_token_module_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_secure_token_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_handler(ngx_http_request_t *r)
{
    ngx_http_secure_token_loc_conf_t  *stlcf;
    ngx_http_secure_token_ctx_t       *stctx;
    ngx_http_complex_value_t          *cv;
    ngx_md5_t                          md5;
    ngx_str_t                          val;
    ngx_int_t                          rc;
    ngx_uint_t                         i;
    size_t                             adjust, len;
    u_char                             hex[32];

    stlcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_module);

    if (!stlcf->enable) {
        return NGX_DECLINED;
    }

    if (stlcf->key.len == 0 || stlcf->md5 == NULL || stlcf->input == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    stctx = ngx_pcalloc(r->pool, sizeof(ngx_http_secure_token_ctx_t));
    if (stctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, stctx, ngx_http_secure_token_module);

    rc = ngx_http_secure_token_parse_input(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (stctx->expire_time < ngx_time()) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: token expired: input: %d now: %d",
                       stctx->expire_time, ngx_time());

        return NGX_HTTP_FORBIDDEN;
    }

    if (stctx->access.len > 0) {
        adjust = stctx->access.data[stctx->access.len - 1] == '*' ? 1 : 0;

        len = r->args.data ? (size_t) (r->args.data - r->unparsed_uri.data) - 1
                           : r->unparsed_uri.len;

        if (len < stctx->access.len - adjust
            || ngx_strncmp(r->unparsed_uri.data,
                           stctx->access.data, stctx->access.len - adjust) != 0)
        {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure token: access mismatch: input: %V uri: %*s",
                           &stctx->access, len, r->unparsed_uri.data);

            return NGX_HTTP_FORBIDDEN;
        }
    }

    cv = stlcf->md5->elts;

    for (i = 0; i < stlcf->md5->nelts; i++) {

        if (ngx_http_complex_value(r, &cv[i], &val) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (val.len == 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_md5_init(&md5);
        ngx_md5_update(&md5, val.data, val.len);
        ngx_md5_final(stctx->md5, &md5);

#if (NGX_DEBUG)
        (void) ngx_hex_dump(hex, stctx->md5, 16);
#endif

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: md5/%d: %*s", i, 32, hex);
    }

#if (!NGX_DEBUG)
    (void) ngx_hex_dump(hex, stctx->md5, 16);
#endif

    if (ngx_strncasecmp(hex, stctx->token.data, 32)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: token mismatch: input: %V expected: %*s",
                       &stctx->token, 32, hex);

        return NGX_HTTP_FORBIDDEN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure token: OK");

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_parse_input(ngx_http_request_t *r)
{
    ngx_http_secure_token_loc_conf_t  *stlcf;
    ngx_http_secure_token_ctx_t       *stctx;
    u_char                            *p, *last, *end;
    size_t                             len;

    stlcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_module);
    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (ngx_http_complex_value(r, stlcf->input, &stctx->input) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (stctx->input.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: missing input");

        return NGX_HTTP_FORBIDDEN;
    }

    if (stlcf->input_sep != '\0') {
        p = stctx->input.data;
        last = stctx->input.data + stctx->input.len;
        end = NULL;

        while (end < last) {
            end = ngx_strlchr(p, last, stlcf->input_sep);
            if (end == NULL) {
                end = last;
            }

            len = end - p;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure token: parse: \"%*s\"", len, p);

            if ((len == 18 && ngx_strncmp(p, "expires", 7) == 0)
                || (len == 17 && ngx_strncmp(p, "expire", 6) == 0))
            {
                stctx->expire_time = ngx_atotm(end - 10, 10);
                if (stctx->expire_time == NGX_ERROR) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "secure token: invalid input");

                    return NGX_HTTP_FORBIDDEN;
                }

                stctx->expire_str.data = end - 10;
                stctx->expire_str.len = 10;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "secure token: input: expire: %d",
                               stctx->expire_time);

            } else if ((len == 38 && ngx_strncmp(p, "token", 5) == 0)
                       || (len == 36 && ngx_strncmp(p, "md5", 3) == 0))
            {
                stctx->token.data = end - 32;
                stctx->token.len = 32;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "secure token: input: token: %V",
                               &stctx->token);

            } else if (len > 7 && ngx_strncmp(p, "access", 6) == 0) {
                stctx->access.data = p + 7;
                stctx->access.len = len - 7;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "secure token: input: access: %V",
                               &stctx->access);
            }

            p = end + 1;
        }

    } else {
        if (stctx->input.len != 43) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure token: invalid input");

            return NGX_HTTP_FORBIDDEN;
        }

        stctx->expire_time = ngx_atotm(stctx->input.data, 10);
        if (stctx->expire_time == NGX_ERROR) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure token: invalid input");

            return NGX_HTTP_FORBIDDEN;
        }

        stctx->expire_str.data = stctx->input.data;
        stctx->expire_str.len = 10;

        stctx->token.data = stctx->input.data + 11;
        stctx->token.len = 32;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: input: expire: %d token: %V",
                       stctx->expire_time, &stctx->token);
    }

    if (stctx->token.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: input: missing token");

        return NGX_HTTP_FORBIDDEN;
    }

    if (stctx->expire_time == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure token: input: missing expire");

        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_key(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_loc_conf_t  *stlcf;

    stlcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_module);

    if (stlcf->key.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = stlcf->key.data;
    v->len = stlcf->key.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_md5(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = stctx->md5;
    v->len = 16;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_input(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL || stctx->input.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = stctx->input.data;
    v->len = stctx->input.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_input_expire(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL || stctx->expire_str.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = stctx->expire_str.data;
    v->len = stctx->expire_str.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_input_expire_native(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL || stctx->expire_time <= 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) &stctx->expire_time;
    v->len = sizeof(time_t);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_input_expire_32bit(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL || stctx->expire_time <= 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) &stctx->expire_time;
    v->len = 4;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_input_token(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL || stctx->token.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = stctx->token.data;
    v->len = stctx->token.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_input_access(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_token_ctx_t  *stctx;

    stctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_module);

    if (stctx == NULL || stctx->access.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = stctx->access.data;
    v->len = stctx->access.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_unparsed_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->args.data ? (size_t) (r->args.data - r->unparsed_uri.data) - 1
                          : r->unparsed_uri.len;

    v->data = r->unparsed_uri.data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_token_variable_lowercase_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  i;

    v->len = r->args.data ? (size_t) (r->args.data - r->unparsed_uri.data) - 1
                          : r->unparsed_uri.len;

    v->data = ngx_palloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < v->len; i++ ) {
        v->data[i] = ngx_tolower(r->unparsed_uri.data[i]);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static char *
ngx_http_secure_token_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_secure_token_loc_conf_t  *stlcf = conf;
    ngx_str_t                         *value = cf->args->elts;
    ngx_http_secure_token_enum_t      *e;
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;
    ngx_uint_t                         i, j, n;

    if (stlcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    e = ngx_http_secure_token_values;
    for (i = 0; e[i].name.len; i++) {
        if ((e[i].name.len == value[1].len)
            && (ngx_strncmp(e[i].name.data, value[1].data, value[1].len) == 0))
        {
            break;
        }
    }

    if (e[i].name.len == 0) {
        if (ngx_strcmp(value[1].data, "off") == 0) {
            stlcf->enable = 0;
            return NGX_CONF_OK;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "secure token: invalid value \"%V\""
                               " in \"%V\" directive", &value[1], &cmd->name);
            return NGX_CONF_ERROR;
        }
    }

    stlcf->enable = 1;

    if (e[i].input[0].len) {
        if (stlcf->input != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"secure_token_input\" directive"
                               " is dupliacate");
            return NGX_CONF_ERROR;
        }

        stlcf->input = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (stlcf->input == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &e[i].input[0];
        ccv.complex_value = stlcf->input;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (e[i].input[1].len) {
            stlcf->input_sep = e[i].input[1].data[0];
        }
    }

    if (e[i].md5[0].len) {
        if (stlcf->md5 != NGX_CONF_UNSET_PTR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"secure_token_md5\" directive is dupliacate");
            return NGX_CONF_ERROR;
        }

        n = e[i].md5[1].len ? 2 : 1;

        stlcf->md5 = ngx_array_create(cf->pool, n,
                                      sizeof(ngx_http_complex_value_t));
        if (stlcf->md5 == NULL) {
            return NGX_CONF_ERROR;
        }

        for (j = 0; j < n; j++) {
            cv = ngx_array_push(stlcf->md5);
            if (cv == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &e[i].md5[j];
            ccv.complex_value = cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_secure_token_conf_md5(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_secure_token_loc_conf_t  *stlcf = conf;

    if (stlcf->md5 != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    return ngx_http_set_predicate_slot(cf, cmd, conf);
}


static char *
ngx_http_secure_token_conf_input(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_secure_token_loc_conf_t  *stlcf = conf;
    ngx_str_t                         *value = cf->args->elts;

    if (stlcf->input != NULL) {
        return "is duplicate";
    }

    if (cf->args->nelts == 3 && value[2].len > 0) {
        stlcf->input_sep = value[2].data[0];
    }

    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}


static void *
ngx_http_secure_token_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_secure_token_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_token_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->key = { 0, NULL };
     *     conf->input = NULL;
     *     conf->input_sep = '\0';
     */

    conf->enable = NGX_CONF_UNSET;
    conf->md5 = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_secure_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_token_loc_conf_t  *prev = parent;
    ngx_http_secure_token_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->key, prev->key, "");
    ngx_conf_merge_ptr_value(conf->md5, prev->md5, NULL)

    if (conf->input == NULL) {
        conf->input = prev->input;
    }

    if (conf->input_sep == '\0') {
        conf->input_sep = prev->input_sep;
    }

    return NGX_CONF_OK;
}
