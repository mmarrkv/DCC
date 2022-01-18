/* unit.c API unit tests driver
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/* Name change compatibility layer no longer need to be included here */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <tests/unit.h>
#include <wolfssl/wolfcrypt/fips_test.h>


int myoptind = 0;
char* myoptarg = NULL;
int unit_test(int argc, char** argv);

#ifndef NO_TESTSUITE_MAIN_DRIVER
int main(int argc, char** argv)
{
    return unit_test(argc, argv);
}
#endif

int unit_test(int argc, char** argv)
{
    int ret = 0;

    (void)argc;
    (void)argv;

#ifdef WOLFSSL_FORCE_MALLOC_FAIL_TEST
    if (argc > 1) {
        int memFailCount = atoi(argv[1]);
        printf("\n--- SET RNG MALLOC FAIL AT %d---\n", memFailCount);
        wolfSSL_SetMemFailCount(memFailCount);
    }
#endif

    printf("starting unit tests...\n");

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    wolfSSL_Debugging_ON();
#endif

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif
#ifdef HAVE_WNR
    if (wc_InitNetRandom(wnrConfig, NULL, 5000) != 0)
        err_sys("Whitewood netRandom global config failed");
#endif /* HAVE_WNR */

#ifndef WOLFSSL_TIRTOS
    ChangeToWolfRoot();
#endif

#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 5)
    if (wc_RunCast_fips(FIPS_CAST_AES_CBC) != 0) {
        err_sys("AES-CBC CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_AES_GCM) != 0) {
        err_sys("AES-GCM CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA1) != 0) {
        err_sys("HMAC-SHA1 CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_256) != 0) {
        err_sys("HMAC-SHA2-256 CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_512) != 0) {
        err_sys("HMAC-SHA2-512 CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA3_256) != 0) {
        err_sys("HMAC-SHA3-256 CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_DRBG) != 0) {
        err_sys("Hash_DRBG CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0) {
        err_sys("RSA sign CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_ECC_PRIMITIVE_Z) != 0) {
        err_sys("ECC Primitive Z CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_DH_PRIMITIVE_Z) != 0) {
        err_sys("DH Primitive Z CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_ECDSA) != 0) {
        err_sys("ECDSA CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_KDF_TLS12) != 0) {
        err_sys("KDF TLSv1.2 CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_KDF_TLS13) != 0) {
        err_sys("KDF TLSv1.3 CAST failed");
    }
    if (wc_RunCast_fips(FIPS_CAST_KDF_SSH) != 0) {
        err_sys("KDF SSHv2.0 CAST failed");
    }
#endif

#ifdef WOLFSSL_ALLOW_SKIP_UNIT_TESTS
    if (argc == 1)
#endif
    {
        ApiTest();

        if ( (ret = HashTest()) != 0){
            printf("hash test failed with %d\n", ret);
            goto exit;
        }
    }

#ifndef NO_WOLFSSL_CIPHER_SUITE_TEST
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
#ifndef SINGLE_THREADED
    if ( (ret = SuiteTest(argc, argv)) != 0){
        printf("suite test failed with %d\n", ret);
        goto exit;
    }
#endif
#endif
#endif /* NO_WOLFSSL_CIPHER_SUITE_TEST */

    SrpTest();

exit:
#ifdef HAVE_WNR
    if (wc_FreeNetRandom() < 0)
        err_sys("Failed to free netRandom context");
#endif /* HAVE_WNR */

    return ret;
}



void wait_tcp_ready(func_args* args)
{
#ifdef SINGLE_THREADED
    (void)args;
#elif defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_mutex_lock(&args->signal->mutex);

    if (!args->signal->ready)
        pthread_cond_wait(&args->signal->cond, &args->signal->mutex);
    args->signal->ready = 0; /* reset */

    pthread_mutex_unlock(&args->signal->mutex);
#else
    (void)args;
#endif
}


void start_thread(THREAD_FUNC fun, func_args* args, THREAD_TYPE* thread)
{
#ifdef SINGLE_THREADED
    (void)fun;
    (void)args;
    (void)thread;
#elif defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_create(thread, 0, fun, args);
    return;
#elif defined (WOLFSSL_TIRTOS)
    /* Initialize the defaults and set the parameters. */
    Task_Params taskParams;
    Task_Params_init(&taskParams);
    taskParams.arg0 = (UArg)args;
    taskParams.stackSize = 65535;
    *thread = Task_create((Task_FuncPtr)fun, &taskParams, NULL);
    if (*thread == NULL) {
        printf("Failed to create new Task\n");
    }
    Task_yield();
#else
    *thread = (THREAD_TYPE)_beginthreadex(0, 0, fun, args, 0, 0);
#endif
}


void join_thread(THREAD_TYPE thread)
{
#ifdef SINGLE_THREADED
    (void)thread;
#elif defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_join(thread, 0);
#elif defined (WOLFSSL_TIRTOS)
    while(1) {
        if (Task_getMode(thread) == Task_Mode_TERMINATED) {
            Task_sleep(5);
            break;
        }
        Task_yield();
    }
#else
    int res = WaitForSingleObject((HANDLE)thread, INFINITE);
    assert(res == WAIT_OBJECT_0);
    res = CloseHandle((HANDLE)thread);
    assert(res);
    (void)res; /* Suppress un-used variable warning */
#endif
}


