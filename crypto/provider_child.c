/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include "internal/provider.h"
#include "internal/cryptlib.h"

DEFINE_STACK_OF(OSSL_PROVIDER)

struct child_prov_globals {
    const OSSL_CORE_HANDLE *handle;
    OSSL_CORE_PROVIDER *curr_prov;
    STACK_OF(OSSL_PROVIDER) *childprovs;
    unsigned int isinited:1;
    CRYPTO_RWLOCK *lock;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
    OSSL_FUNC_core_provider_do_all_fn *c_prov_do_all;
    OSSL_FUNC_core_provider_name_fn *c_prov_name;
    OSSL_FUNC_core_provider_get0_provider_ctx_fn *c_prov_get0_provider_ctx;
    OSSL_FUNC_core_provider_get0_dispatch_fn *c_prov_get0_dispatch;
};

static void *child_prov_ossl_ctx_new(OSSL_LIB_CTX *libctx)
{
    return OPENSSL_zalloc(sizeof(struct child_prov_globals));
}

/* Wrapper with a void return type for use with sk_OSSL_PROVIDER_pop_free */
static void ossl_prov_free(OSSL_PROVIDER *prov)
{
    OSSL_PROVIDER_unload(prov);
}

static void child_prov_ossl_ctx_free(void *vgbl)
{
    struct child_prov_globals *gbl = vgbl;

    sk_OSSL_PROVIDER_pop_free(gbl->childprovs, ossl_prov_free);
    CRYPTO_THREAD_lock_free(gbl->lock);
    OPENSSL_free(gbl);
}

static const OSSL_LIB_CTX_METHOD child_prov_ossl_ctx_method = {
    OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY,
    child_prov_ossl_ctx_new,
    child_prov_ossl_ctx_free,
};

static OSSL_provider_init_fn ossl_child_provider_init;

static int ossl_child_provider_init(const OSSL_CORE_HANDLE *handle,
                                    const OSSL_DISPATCH *in,
                                    const OSSL_DISPATCH **out,
                                    void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_LIB_CTX *ctx;
    struct child_prov_globals *gbl;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    /*
     * We need an OSSL_LIB_CTX but c_get_libctx returns OPENSSL_CORE_CTX. We are
     * a built-in provider and so we can get away with this cast. Normal
     * providers can't do this.
     */
    ctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

    gbl = ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                &child_prov_ossl_ctx_method);
    if (gbl == NULL)
        return 0;

    *provctx = gbl->c_prov_get0_provider_ctx(gbl->curr_prov);
    *out = gbl->c_prov_get0_dispatch(gbl->curr_prov);

    return 1;
}

static int provider_create_child_cb(OSSL_CORE_PROVIDER *prov, void *cbdata)
{
    OSSL_LIB_CTX *ctx = cbdata;
    struct child_prov_globals *gbl;
    const char *provname;
    OSSL_PROVIDER *cprov;

    gbl = ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                &child_prov_ossl_ctx_method);
    if (gbl == NULL)
        return 0;

    provname = gbl->c_prov_name(prov);

    /*
     * We're operating under a lock so we can store the "current" provider in
     * the global data.
     */
    gbl->curr_prov = prov;

    /*
     * Create it - passing 1 as final param so we don't try and recursively init
     * children
     */
    if ((cprov = ossl_provider_new(ctx, provname, ossl_child_provider_init,
                                   1)) == NULL)
        return 0;

    if (!ossl_provider_activate(cprov, 0)) {
        ossl_provider_free(cprov);
        return 0;
    }
    ossl_provider_set_child(cprov);

    if (!sk_OSSL_PROVIDER_push(gbl->childprovs, cprov)) {
        OSSL_PROVIDER_unload(cprov);
        return 0;
    }

    return 1;
}

int ossl_provider_init_child_providers(OSSL_LIB_CTX *ctx)
{
    struct child_prov_globals *gbl;

    /* Should never happen */
    if (ctx == NULL)
        return 0;

    gbl = ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                &child_prov_ossl_ctx_method);
    if (gbl == NULL)
        return 0;

    if (!CRYPTO_THREAD_read_lock(gbl->lock))
        return 0;
    if (gbl->isinited) {
        CRYPTO_THREAD_unlock(gbl->lock);
        return 1;
    }
    CRYPTO_THREAD_unlock(gbl->lock);

    if (!CRYPTO_THREAD_write_lock(gbl->lock))
        return 0;
    if (!gbl->isinited) {
        if (!gbl->c_prov_do_all(gbl->c_get_libctx(gbl->handle),
                                provider_create_child_cb, ctx)) {
            CRYPTO_THREAD_unlock(gbl->lock);
            return 0;
        }
        gbl->isinited = 1;
    }
    CRYPTO_THREAD_unlock(gbl->lock);

    return 1;
}

int ossl_provider_init_as_child(OSSL_LIB_CTX *ctx,
                                const OSSL_CORE_HANDLE *handle,
                                const OSSL_DISPATCH *in)
{
    struct child_prov_globals *gbl;

    if (ctx == NULL)
        return 0;

    gbl = ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_CHILD_PROVIDER_INDEX,
                                &child_prov_ossl_ctx_method);
    if (gbl == NULL)
        return 0;

    gbl->handle = handle;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            gbl->c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_CORE_PROVIDER_DO_ALL:
            gbl->c_prov_do_all = OSSL_FUNC_core_provider_do_all(in);
            break;
        case OSSL_FUNC_CORE_PROVIDER_NAME:
            gbl->c_prov_name = OSSL_FUNC_core_provider_name(in);
            break;
        case OSSL_FUNC_CORE_PROVIDER_GET0_PROVIDER_CTX:
            gbl->c_prov_get0_provider_ctx
                = OSSL_FUNC_core_provider_get0_provider_ctx(in);
            break;
        case OSSL_FUNC_CORE_PROVIDER_GET0_DISPATCH:
            gbl->c_prov_get0_dispatch = OSSL_FUNC_core_provider_get0_dispatch(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (gbl->c_prov_do_all == NULL
            || gbl->c_prov_name == NULL
            || gbl->c_prov_get0_provider_ctx == NULL
            || gbl->c_prov_get0_dispatch == NULL)
        return 0;

    gbl->childprovs = sk_OSSL_PROVIDER_new_null();
    if (gbl->childprovs == NULL)
        return 0;
    gbl->lock = CRYPTO_THREAD_lock_new();
    if (gbl->lock == NULL)
        return 0;

    return 1;
}
