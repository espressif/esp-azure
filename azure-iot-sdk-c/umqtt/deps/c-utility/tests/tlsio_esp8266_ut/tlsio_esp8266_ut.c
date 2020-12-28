// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdlib.h>
#include <stdio.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

/**
 * Include the C standards here.
 */
#include <stddef.h>
#include <time.h>

/**
 * Include the test tools.
 */
#include "azure_macro_utils/macro_utils.h"
#include "testrunnerswitcher.h"
#include "umock_c/umock_c.h"
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umock_c_negative_tests.h"

/**
 * Include the mockable headers here.
 */
#define ENABLE_MOCKS
#include "../../adapters/esp8266_mock.h"
#undef ENABLE_MOCKS

/**
 * Include the target header after the ENABLE_MOCKS session.
 */
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/tlsio.h"

#define TEST_CREATE_CONNECTION_HOST_NAME (const char*)"https://test.azure-devices.net"
#define TEST_CREATE_CONNECTION_PORT (int)443

static const TLSIO_CONFIG tlsio_config = { TEST_CREATE_CONNECTION_HOST_NAME, TEST_CREATE_CONNECTION_PORT, NULL, NULL };

static int g_ssl_write_success = 1;
static int g_ssl_read_returns_data = 1;
static size_t g_on_bytes_received_buffer_size = 0;

static int g_gethostbyname_success = 1;
static int g_socket_success = 1;
static int g_setsockopt_success = 1;
static int g_bind_success = 1;
static int g_getsockopt_success = 1;
static int g_connect_success = 1;
static int g_ssl_lwip_select_success = 1;
static int g_ssl_ctx_new_success = 1;
static int g_ssl_new_success = 1;
static int g_ssl_set_fd_success = 1;
static int g_ssl_connect_success = 1;
static int g_ssl_shutdown_success = 1;
static int g_ssl_TLSv1clientmethod_success = 1;
static int g_ssl_fd_isset = 0;
static int g_ssl_get_error_success = 1;
static int g_socket_close_success = 1;
static SSL_CTX* g_ctx = NULL;
static SSL* g_ssl = NULL;
static SSL_METHOD* g_sslmethod = NULL;
static void* g_mallocptr = NULL;
static char* g_destination = NULL;

#define MAX_RETRY 20
#define RECEIVE_BUFFER_SIZE 1024

void* my_gballoc_malloc(size_t size)
{
    g_mallocptr = malloc(size);
    return g_mallocptr;
}

void* my_gballoc_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void my_gballoc_free(void* ptr)
{
    free(ptr);
}

typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPENING,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_CLOSING,
    TLSIO_STATE_ERROR
} TLSIO_STATE;

typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_open_complete_context;
    void* on_io_close_complete_context;
    void* on_io_error_context;
    SSL* ssl;
    SSL_CTX* ssl_context;
    TLSIO_STATE tlsio_state;
    char* hostname;
    int port;
    char* certificate;
    const char* x509certificate;
    const char* x509privatekey;
    int sock;
    ip_addr_t target_ip;
} TLS_IO_INSTANCE;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

int my_mallocAndStrcpy_s(char** destination, const char* source){
    (void)(source);
    *destination = (char*)malloc(1);
    g_destination = *destination;
    return 0;
}
int my_SSL_get_error(const SSL *ssl, int ret_code){
    (void)(ret_code), (void)(ssl);
    if (g_ssl_get_error_success == 1){
        return SSL_ERROR_WANT_READ;
    }else{
        return 0;
    }

}
int my_FD_ISSET(int n, void* p){
    (void)(n),(void)(p);
    if(g_ssl_fd_isset == 0){
        g_ssl_fd_isset++;
        return 1;
    }else{
        return 0;
    }
}

int my_lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
               struct timeval *timeout){
    (void)(maxfdp1),(void)(readset),(void)(writeset),(void)(exceptset),(void)(timeout);

    if(g_ssl_lwip_select_success == 1)
    {
        return 1;
    }else{
        return 0;
    }
}

int my_SSL_write(SSL *ssl, const void *buffer, int len){
    (void)(ssl),(void)(buffer);

    if (g_ssl_write_success){
        return len;
    }else{
        return 0;
    }
}

void my_SSL_CTX_free(SSL_CTX *ctx){
    (void)(ctx);
}

void my_SSL_free(SSL *ssl){
    (void)(ssl);
}

int my_SSL_read(SSL *ssl, void *buffer, int len){
    (void)(ssl),(void)(buffer);
    if (g_ssl_read_returns_data){
        return len;
    }else{
        return 0;
    }
}

int my_SSL_connect(SSL *ssl){
    (void)(ssl);
    if (g_ssl_connect_success == 1){
        return 1;
    }else{
        return -1;
    }
}

int my_SSL_shutdown(SSL *ssl){
    (void)(ssl);
    if (g_ssl_shutdown_success == 1){
        return 0;
    }else{
        return -1;
    }
}

int my_socket(int domain, int type, int protocol){
    (void)(domain),(void)(type), (void)(protocol);
    if (g_socket_success == 1){
        return 0;
    }else{
        return -1;
    }
}

int my_SSL_set_fd(SSL *ssl, int fd){
    (void)(ssl),(void)(fd);
    if (g_ssl_set_fd_success == 1){
        return 1;
    }else{
        return 0;
    }
}
//NOTE: malloc(1) is used here since SSL is defined as void in esp8266_mock.h
SSL* my_SSL_new(SSL_CTX *ssl_ctx){
    (void)(ssl_ctx);
    if (g_ssl_new_success == 1){
         g_ssl = (SSL*)malloc(1);
        return g_ssl;
    }else{
        return NULL;
    }
}

//NOTE: malloc(1) is used here since SSL_CTX is defined as void in esp8266_mock.h
SSL_CTX* my_SSL_CTX_new(SSL_METHOD *method){
    (void)(method);
    if(g_ssl_ctx_new_success == 1)
    {
        if(method != NULL){
            g_ctx = (SSL_CTX*)malloc(1);
            return g_ctx;
        }
        else
        {
            return NULL;
        }
    }else{
        return NULL;
    }
}

void my_SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len)
{
    (void)(ctx),(void)(len);

}

int my_fcntl(int s, int cmd, int val)
{
    (void)(s);
    (void)(cmd);
    (void)(val);
    return 0;
}
err_t my_netconn_gethostbyname(const char *name, ip_addr_t *target_ip){
    (void)(name),(void)(target_ip);
    if (g_gethostbyname_success == 1){
        return 0;
    }else{
        return -1;
    }
}

//NOTE: malloc(1) is used here since SSL_METHOD is defined as void in esp8266_mock.h
SSL_METHOD* my_TLSv1_client_method(void){
    if (g_ssl_TLSv1clientmethod_success == 1){
        g_sslmethod = (SSL_METHOD*)malloc(1);
        return g_sslmethod;
    }else{
        return NULL;
    }
}

int my_bind(int s, const struct sockaddr* name, socklen_t namelen){
    (void)(s),(void)(name),(void)(namelen);
    if (g_bind_success == 1){
        return 0;
    }else{
        return -1;
    }
}

int my_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen){
    (void)(s),(void)(level),(void)(optname),(void)(optval),(void)(optlen);
    if (g_setsockopt_success == 1){
        return 0;
    }else{
        return -1;
    }
}

int my_close(int s){
    (void)(s);
    if (g_socket_close_success == 1){
        return 0;
    } else{
        return 1;
    }
}

int my_connect(int s, const struct sockaddr *name, socklen_t namelen){
    (void)(s),(void)(name), (void)(namelen);
    if (g_connect_success == 1){
        return 0;
    }else{
        return -1;
    }
}
#undef   EINPROGRESS
#define  EINPROGRESS    115  /* Operation now in progress */
int my_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen){
    (void)(s), (void)(level), (void)(optname), (void)(optval), (void)(optlen);
    if (g_getsockopt_success == 1){
        return EINPROGRESS;
    }else{
        return -1;
    }
}

void my_os_delay_us(int us){
    (void)(us);
}

static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    (void)(context), (void)(buffer), (void)(size);
    g_on_bytes_received_buffer_size = size;
}

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/optionhandler.h"

IMPLEMENT_UMOCK_C_ENUM_TYPE(IO_OPEN_RESULT, IO_OPEN_RESULT_VALUES);
IMPLEMENT_UMOCK_C_ENUM_TYPE(IO_SEND_RESULT, IO_SEND_RESULT_VALUES);


MOCK_FUNCTION_WITH_CODE(, void, test_on_io_error, void*, context)
MOCK_FUNCTION_END();
MOCK_FUNCTION_WITH_CODE(, void, test_on_bytes_received, void*, context, const unsigned char*, buffer, size_t, size)
MOCK_FUNCTION_END();
MOCK_FUNCTION_WITH_CODE(, void, test_on_io_open_complete, void*, context, IO_OPEN_RESULT, open_result)
MOCK_FUNCTION_END();
MOCK_FUNCTION_WITH_CODE(, void, test_on_io_close_complete, void*, context)
MOCK_FUNCTION_END();
MOCK_FUNCTION_WITH_CODE(, void, test_on_send_complete, void*, context, IO_SEND_RESULT, send_result)
MOCK_FUNCTION_END();
#undef ENABLE_MOCKS

 /**
  * You can create some global variables that your test will need in some way.
  */
static void* g_GenericPointer;

/**
  * Umock error will helps you to identify errors in the test suite or in the way that you are
  *    using it, just keep it as is.
  */
MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%" PRI_MU_ENUM "", MU_ENUM_VALUE(UMOCK_C_ERROR_CODE, error_code));
}

/**
 * This is necessary for the test suite, just keep as is.
 */
static TEST_MUTEX_HANDLE g_testByTest;

/**
 * Tests begin here.
 *
 *   RUN_TEST_SUITE(tlsio_esp8266_ut, failedTestCount);
 *
 */
BEGIN_TEST_SUITE(tlsio_esp8266_ut)

    /**
     * This is the place where we initialize the test system. Replace the test name to associate the test
     *   suite with your test cases.
     * It is called once, before start the tests.
     */
    TEST_SUITE_INITIALIZE(a)
    {
        int result;
        g_testByTest = TEST_MUTEX_CREATE();
        ASSERT_IS_NOT_NULL(g_testByTest);

        (void)umock_c_init(on_umock_c_error);

        result = umocktypes_charptr_register_types();
        ASSERT_ARE_EQUAL(int, 0, result);

        /**
         * It is necessary to identify the types defined on your target. With it, the test system will
         *    know how to use it.
         *
         * On the target.h example, there is the type TARGET_HANDLE that is a void*
         */
        //REGISTER_UMOCK_ALIAS_TYPE(CALLEE_HANDLE, void*);


        /**
         * Or you can combine, for example, in the success case malloc will call my_gballoc_malloc, and for
         *    the failed cases, it will return NULL.
         */
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_realloc, my_gballoc_realloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_realloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);


        //REGISTER_GLOBAL_MOCK_HOOK(OptionHandler_Create, my_OptionHandler_Create);
        REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, my_mallocAndStrcpy_s);
        REGISTER_GLOBAL_MOCK_HOOK(lwip_select, my_lwip_select);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_write, my_SSL_write);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_CTX_free, my_SSL_CTX_free);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_free, my_SSL_free);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_read, my_SSL_read);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_connect, my_SSL_connect);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_shutdown, my_SSL_shutdown);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_set_fd, my_SSL_set_fd);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_new, my_SSL_new);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_CTX_new, my_SSL_CTX_new);
        REGISTER_GLOBAL_MOCK_HOOK(netconn_gethostbyname, my_netconn_gethostbyname);
        REGISTER_GLOBAL_MOCK_HOOK(TLSv1_client_method, my_TLSv1_client_method);
        REGISTER_GLOBAL_MOCK_HOOK(bind, my_bind);
        REGISTER_GLOBAL_MOCK_HOOK(getsockopt, my_getsockopt);
        REGISTER_GLOBAL_MOCK_HOOK(socket, my_socket);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_CTX_set_default_read_buffer_len, my_SSL_CTX_set_default_read_buffer_len);
        REGISTER_GLOBAL_MOCK_HOOK(setsockopt, my_setsockopt);
        REGISTER_GLOBAL_MOCK_HOOK(close, my_close);
        REGISTER_GLOBAL_MOCK_HOOK(connect, my_connect);
        REGISTER_GLOBAL_MOCK_HOOK(FD_ISSET, my_FD_ISSET);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_get_error, my_SSL_get_error);
        REGISTER_GLOBAL_MOCK_HOOK(fcntl, my_fcntl);
        REGISTER_TYPE(IO_SEND_RESULT, IO_SEND_RESULT);
        REGISTER_TYPE(IO_OPEN_RESULT, IO_OPEN_RESULT);

        /**
         * You can initialize other global variables here, for instance image that you have a standard void* that will be converted
         *   any pointer that your test needs.
         */
        g_GenericPointer = malloc(1);
        ASSERT_IS_NOT_NULL(g_GenericPointer);
    }

    /**
     * The test suite will call this function to cleanup your machine.
     * It is called only once, after all tests is done.
     */
    TEST_SUITE_CLEANUP(TestClassCleanup)
    {
        free(g_GenericPointer);

        umock_c_deinit();

        TEST_MUTEX_DESTROY(g_testByTest);
    }

    /**
     * The test suite will call this function to prepare the machine for the new test.
     * It is called before execute each test.
     */
    TEST_FUNCTION_INITIALIZE(initialize)
    {
        if (TEST_MUTEX_ACQUIRE(g_testByTest))
        {
            ASSERT_FAIL("Could not acquire test serialization mutex.");
        }

        g_ssl_fd_isset = 1;

        umock_c_reset_all_calls();
    }

    /**
     * The test suite will call this function to cleanup your machine for the next test.
     * It is called after execute each test.
     */
    TEST_FUNCTION_CLEANUP(cleans)
    {
        TEST_MUTEX_RELEASE(g_testByTest);
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_063: [ The tlsio_openssl_dowork shall execute the async jobs for the tlsio. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_069: [ If the tlsio state is TLSIO_STATE_OPEN, the tlsio_openssl_dowork shall read data from the ssl client. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_070: [ If there are received data in the ssl client, the tlsio_openssl_dowork shall read this data and call the on_bytes_received with the pointer to the buffer with the data. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_075: [ The tlsio_openssl_dowork shall create a buffer to store the data received from the ssl client. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_076: [ The tlsio_openssl_dowork shall delete the buffer to store the data received from the ssl client. ] */
    TEST_FUNCTION(tlsio_openssl_dowork_withdata__succeed)
    {
        ///arrange
        TLS_IO_INSTANCE instance;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        g_ssl_read_returns_data = 1;
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.on_bytes_received = on_bytes_received;
        instance.tlsio_state = TLSIO_STATE_OPEN;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        EXPECTED_CALL(SSL_read(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));

        ///act
        tlsioInterfaces->concrete_io_dowork(&instance);

        ///assert
        ASSERT_ARE_EQUAL(size_t, g_on_bytes_received_buffer_size, RECEIVE_BUFFER_SIZE);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ///cleanup
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_071: [** If there are no received data in the ssl client, the tlsio_openssl_dowork shall do nothing. ] */
    TEST_FUNCTION(tlsio_openssl_dowork_withoutdata__succeed)
    {
        ///arrange
        TLS_IO_INSTANCE instance;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        g_ssl_read_returns_data = 0;
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.on_bytes_received = on_bytes_received;
        instance.tlsio_state = TLSIO_STATE_OPEN;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        EXPECTED_CALL(SSL_read(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));

        ///act
        tlsioInterfaces->concrete_io_dowork(&instance);

        ///assert
        ASSERT_ARE_EQUAL(size_t, g_on_bytes_received_buffer_size, 0);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ///cleanup
    }


    /* Tests_SRS_TLSIO_SSL_ESP8266_99_074: [ If the tlsio handle is NULL, the tlsio_openssl_dowork shall not do anything. ] */
    TEST_FUNCTION(tlsio_openssl_dowork__failed)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        tlsioInterfaces->concrete_io_dowork(NULL);

        ///assert
        ///cleanup
    }


    /* Tests_SRS_TLSIO_SSL_ESP8266_99_053: [ The tlsio_openssl_send shall send all bytes in a buffer to the ssl connection. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_054: [ The tlsio_openssl_send shall use the provided on_io_send_complete callback function address. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_055: [ The tlsio_openssl_send shall use the provided on_io_send_complete_context handle. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_056: [ The ssl will continue to send all data in the buffer until all bytes have been sent. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_058: [ If the ssl finish to send all bytes in the buffer, then tlsio_openssl_send shall call the on_send_complete with IO_SEND_OK, and return 0 ] */
    TEST_FUNCTION(tlsio_openssl_send__SSL_write__succeed)
    {
        ///arrange
        int result = 0;
        TLS_IO_INSTANCE instance;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        unsigned char test_buffer[] = { 0x42, 0x43 };
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.tlsio_state = TLSIO_STATE_OPEN;
        g_ssl_write_success = 1;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        EXPECTED_CALL(SSL_write(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG));
        STRICT_EXPECTED_CALL(test_on_send_complete((void*)0x4242, IO_SEND_OK));

        ///act
        result = tlsioInterfaces->concrete_io_send(&instance, test_buffer, sizeof(test_buffer), test_on_send_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_EQUAL(int, result, 0);
        ///cleanup
     }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_060: [ If the tls_io handle is NULL, the tlsio_openssl_send shall not do anything, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_send_null_handle__failed)
    {
        ///arrange
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        result = tlsioInterfaces->concrete_io_send(NULL, NULL, 0, NULL, NULL);

        ///assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_061: [ If the buffer is NULL, the tlsio_openssl_send shall not do anything, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_send__SSL_write_null_buffer__failed)
    {
        ///arrange
        int result = 0;
        TLS_IO_INSTANCE instance;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.tlsio_state = TLSIO_STATE_OPEN;
        g_ssl_write_success = 1;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        result = tlsioInterfaces->concrete_io_send(&instance, NULL, 0, test_on_send_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_NOT_EQUAL(int, result, 0);
        ///cleanup
     }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_062: [ If the size is 0, the tlsio_openssl_send shall not do anything, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_send__SSL_write_size_zero__failed)
    {
        ///arrange
        int result = 0;
        TLS_IO_INSTANCE instance;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        unsigned char test_buffer[] = {0x42};
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.tlsio_state = TLSIO_STATE_OPEN;
        g_ssl_write_success = 1;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        result = tlsioInterfaces->concrete_io_send(&instance, test_buffer, 0, test_on_send_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_NOT_EQUAL(int, result, 0);
        ///cleanup
     }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_059: [ If the tlsio state is not TLSIO_STATE_OPEN, the tlsio_openssl_send shall return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_send_wrong_state__failed)
    {
        ///arrange
        int result;
        TLS_IO_INSTANCE instance;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ///act
        result = tlsioInterfaces->concrete_io_send(&instance, NULL, 0,  NULL, NULL);

        ///assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_057: [ If the ssl was not able to send all the bytes in the buffer, the tlsio_openssl_send shall call the on_send_complete with IO_SEND_ERROR, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_send__SSL_write__failed)
    {
        ///arrange
        int result = 0;
        TLS_IO_INSTANCE instance;
        unsigned char test_buffer[] = { 0x42, 0x43 };
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.tlsio_state = TLSIO_STATE_OPEN;
        g_ssl_write_success = 0;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        EXPECTED_CALL(SSL_write(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG));
        EXPECTED_CALL(SSL_shutdown(IGNORED_PTR_ARG));

        STRICT_EXPECTED_CALL(test_on_send_complete((void*)0x4242, IO_SEND_ERROR));

        ///act
        result = tlsioInterfaces->concrete_io_send(&instance, test_buffer, sizeof(test_buffer), test_on_send_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, result, 0);
        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_043: [ The tlsio_openssl_close shall start the process to close the ssl connection. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_045: [ The tlsio_openssl_close shall store the provided on_io_close_complete callback function address. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_046: [ The tlsio_openssl_close shall store the provided on_io_close_complete_context handle. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_047: [ If tlsio_openssl_close get success to start the process to close the ssl connection, it shall set the tlsio state as TLSIO_STATE_CLOSING, and return 0. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_050: [ If tlsio_openssl_close successfully destroys the ssl connection, it shall set the tlsio state as TLSIO_STATE_NOT_OPEN, and return 0. ] */
    /* Tests_SRS_TLSIO_SSL_ESP8266_99_051: [ If tlsio_openssl_close successfully destroys the ssl connection, it shall call on_io_close_complete. ] */
    TEST_FUNCTION(tlsio_openssl_close__succeed)
    {
        ///arrange
        int result;
        TLS_IO_INSTANCE instance;
        SSL_CTX *ctx;
        SSL *ssl;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        g_ssl_TLSv1clientmethod_success = 0;
        ctx = SSL_CTX_new(TLSv1_client_method());
        ASSERT_IS_NULL(ctx);
        g_ssl_TLSv1clientmethod_success = 1;
        ctx = SSL_CTX_new(TLSv1_client_method());
        ASSERT_IS_NOT_NULL(ctx);
        ssl = SSL_new(ctx);
        g_ssl_shutdown_success = 1;
        g_socket_close_success = 1;

        instance.tlsio_state = TLSIO_STATE_OPEN;
        instance.ssl = ssl;
        instance.ssl_context = ctx;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        STRICT_EXPECTED_CALL(SSL_free(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(close(IGNORED_NUM_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_free(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(test_on_io_close_complete((void*)0x4242));
        ///act
        result = tlsioInterfaces->concrete_io_close(&instance, test_on_io_close_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_EQUAL(int, 0, result);
        ASSERT_ARE_EQUAL(int, (int)TLSIO_STATE_NOT_OPEN, instance.tlsio_state);
        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if(g_ssl != NULL){
            free(g_ssl);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }


    /* Tests_SRS_TLSIO_SSL_ESP8266_99_048: [ If the tlsio state is TLSIO_STATE_NOT_OPEN, TLSIO_STATE_OPENING, or TLSIO_STATE_CLOSING, the tlsio_openssl_close shall set the tlsio state as TLSIO_STATE_ERROR, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_close_wrong_state__failed)
    {
        ///arrange
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        TLS_IO_INSTANCE instance;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ///act
        result = tlsioInterfaces->concrete_io_close(&instance, test_on_io_close_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        instance.tlsio_state = TLSIO_STATE_CLOSING;
        ///act
        result = tlsioInterfaces->concrete_io_close(&instance, NULL, NULL);

        ///assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result);
        ASSERT_ARE_EQUAL(int, (int)TLSIO_STATE_ERROR, instance.tlsio_state);
        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_049: [ If the tlsio_handle is NULL, the tlsio_openssl_close shall not do anything, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_close_null_handle__failed)
    {
        ///arrange
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        result = tlsioInterfaces->concrete_io_close(NULL, test_on_io_close_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);
        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_052: [ If tlsio_openssl_close fails to shutdown the ssl connection, it shall set the tlsio state as TLSIO_STATE_ERROR, and return _LINE_, and call on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_close_shutdown__failed)
    {
        ///arrange
        int result;
        TLS_IO_INSTANCE instance;
        SSL_CTX *ctx;
        SSL *ssl;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        memset(&instance, 0, sizeof(TLS_IO_INSTANCE));
        g_ssl_TLSv1clientmethod_success = 0;
        ctx = SSL_CTX_new(TLSv1_client_method());
        ASSERT_IS_NULL(ctx);
        g_ssl_TLSv1clientmethod_success = 1;
        ctx = SSL_CTX_new(TLSv1_client_method());
        ASSERT_IS_NOT_NULL(ctx);
        ssl = SSL_new(ctx);
        g_socket_close_success = 0;

        instance.tlsio_state = TLSIO_STATE_OPEN;
        instance.ssl = ssl;
        instance.ssl_context = ctx;
        instance.on_io_error = test_on_io_error;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        STRICT_EXPECTED_CALL(SSL_free(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(close(IGNORED_NUM_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_free(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(test_on_io_error(NULL));
        ///act
        result = tlsioInterfaces->concrete_io_close(&instance, test_on_io_close_complete, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);
        ASSERT_ARE_EQUAL(int, (int)TLSIO_STATE_ERROR, instance.tlsio_state);
        ///cleanup
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if(g_ssl != NULL){
            free(g_ssl);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_021: [ The tlsio_openssl_destroy shall destroy a created instance of the tlsio for ESP8266 identified by the CONCRETE_IO_HANDLE. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_022: [ The tlsio_openssl_destroy shall free all memory allocated for tlsio_instance. ] */
    TEST_FUNCTION(tlsio_openssl_destroy__succeed)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        TLS_IO_INSTANCE* instance = (TLS_IO_INSTANCE*)malloc(sizeof(TLS_IO_INSTANCE));
        memset(instance, 0, sizeof(TLS_IO_INSTANCE));
        instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        umock_c_reset_all_calls();
        STRICT_EXPECTED_CALL(free(instance));

        ///act
        tlsioInterfaces->concrete_io_destroy(instance);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ///cleanup
    }


    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_024: [ If the tlsio_handle is NULL, the tlsio_openssl_destroy shall not do anything. ] */
    TEST_FUNCTION(tlsio_openssl_destroy_NULL_handle__failed)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        tlsioInterfaces->concrete_io_destroy(NULL);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ///cleanup
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_025: [ If the tlsio state is TLSIO_STATE_OPENING, TLSIO_STATE_OPEN, or TLSIO_STATE_CLOSING, the tlsio_openssl_destroy shall destroy the tlsio, but log an error. ] */
    TEST_FUNCTION(tlsio_openssl_destroy_wrong_state__failed)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        TLS_IO_INSTANCE* instance = (TLS_IO_INSTANCE*)malloc(sizeof(TLS_IO_INSTANCE));
        memset(instance, 0, sizeof(TLS_IO_INSTANCE));
        instance->tlsio_state = TLSIO_STATE_OPENING;
        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();
        STRICT_EXPECTED_CALL(free(instance));

        ///act
        tlsioInterfaces->concrete_io_destroy(instance);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ///cleanup
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_018: [ The tlsio_openssl_open shall convert the provide hostName to an IP address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_026: [ The tlsio_openssl_open shall start the process to open the ssl connection with the host provided in the tlsio_openssl_create. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_030: [ The tlsio_openssl_open shall store the provided on_bytes_received callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_031: [ The tlsio_openssl_open shall store the provided on_bytes_received_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_034: [ If tlsio_openssl_open get success to open the ssl connection, it shall set the tlsio state as TLSIO_STATE_OPEN, and return 0. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_041: [ If the tlsio_openssl_open get success to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_OK. ] */
    TEST_FUNCTION(tlsio_openssl_open__succeed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));

        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;

        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(connect(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);

        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(SSL_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_set_fd(IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);

        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
          IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(SSL_connect(IGNORED_PTR_ARG)).IgnoreArgument(1);

        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_OK));
        STRICT_EXPECTED_CALL(os_delay_us(IGNORED_NUM_ARG)).IgnoreArgument(1);

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(int, 0, result);
        /**
         * The follow assert will compare the expected calls with the actual calls. If it is different,
         *    it will show the serialized strings with the differences in the log.
         */
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_EQUAL(int, (int)TLSIO_STATE_OPEN, tls_io_instance.tlsio_state);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if(g_ssl != NULL){
            free(g_ssl);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }

    }


    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_035: [ If the tlsio state is not TLSIO_STATE_NOT_OPEN and not TLSIO_STATE_ERROR, then tlsio_openssl_open shall set the tlsio state as TLSIO_STATE_ERROR, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    TEST_FUNCTION(tlsio_openssl_open_invalid_state__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        tls_io_instance.tlsio_state = TLSIO_STATE_OPENING;

        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));
        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);
        ASSERT_ARE_EQUAL(int, (int)TLSIO_STATE_ERROR, tls_io_instance.tlsio_state);
        ///cleanup
    }


    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_036: [ If the tls_io handle is NULL, the tlsio_openssl_open shall not do anything, and return _LINE_. ] */
    TEST_FUNCTION(tlsio_openssl_open_NULL_handle__failed)
    {
        ///arrange
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        result = tlsioInterfaces->concrete_io_open(NULL, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_019: [ If the WiFi cannot find the IP for the hostName, the tlsio_openssl_open shall return __LINE__. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_027: [ The tlsio_openssl_open shall set the tlsio to try to open the connection for MAX_RETRY times before assuming that connection failed. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_gethostbyname__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        int retry = 0;
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 0;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;

        umock_c_reset_all_calls();

        do{
            STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        }while(retry++ < MAX_RETRY);

        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));
        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_080: [ If socket failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_socket__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 0;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_081: [ If setsockopt failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_setsockopt__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 0;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_082: [ If bind failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_bind__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 0;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_083: [ If connect and getsockopt failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_connect_getsockopt__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 0;
        g_getsockopt_success = 0;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(connect(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(getsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_084: [ If lwip_select failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_027: [ The tlsio_openssl_open shall set the tlsio to try to open the connection for MAX_RETRY times before assuming that connection failed. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_lwip_select__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 0;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(connect(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(getsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_085: [ If SSL_CTX_new failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_sslctxnew__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 0;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_087: [ If SSL_new failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_sslnew__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 0;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(connect(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);

        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(SSL_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_088: [ If SSL_set_fd failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_sslsetfd__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 0;
        g_ssl_connect_success = 1;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(connect(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);

        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(SSL_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_set_fd(IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_ssl != NULL){
            free(g_ssl);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_089: [ If SSL_connect failed, the tlsio_openssl_open shall return __LINE__. ]*/
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_042: [ If the tlsio_openssl_open retry SSL_connect to open more than MAX_RETRY times without success, it shall return __LINE__. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ] */
    TEST_FUNCTION(tlsio_openssl_open_sslconnect__failed)
    {
        ///arrange
        TLS_IO_INSTANCE tls_io_instance;
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        int retry = 0;
        memset(&tls_io_instance, 0, sizeof(TLS_IO_INSTANCE));
        tls_io_instance.tlsio_state = TLSIO_STATE_NOT_OPEN;
        ASSERT_IS_NOT_NULL(tlsioInterfaces);
        g_gethostbyname_success = 1;
        g_socket_success = 1;
        g_setsockopt_success = 1;
        g_bind_success = 1;
        g_connect_success = 1;
        g_ssl_lwip_select_success = 1;
        g_ssl_ctx_new_success = 1;
        g_ssl_new_success = 1;
        g_ssl_set_fd_success = 1;
        g_ssl_connect_success = 0;
        g_ssl_fd_isset = 0;
        g_ssl_get_error_success = 1;

        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(netconn_gethostbyname(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(TLSv1_client_method());
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_PTR_ARG)).IgnoreArgument(1);
        STRICT_EXPECTED_CALL(SSL_CTX_set_default_read_buffer_len(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(socket(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(setsockopt(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(fcntl(IGNORED_NUM_ARG,IGNORED_NUM_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(bind(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(connect(IGNORED_NUM_ARG,IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3);
        STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);

        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        STRICT_EXPECTED_CALL(SSL_new(IGNORED_PTR_ARG)).IgnoreArgument(1);

        STRICT_EXPECTED_CALL(SSL_set_fd(IGNORED_PTR_ARG, IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
        while(retry < MAX_RETRY){
            STRICT_EXPECTED_CALL(lwip_select(IGNORED_NUM_ARG, IGNORED_PTR_ARG,
              IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2).IgnoreArgument(3).IgnoreArgument(4).IgnoreArgument(5);
            STRICT_EXPECTED_CALL(FD_ISSET(IGNORED_NUM_ARG,IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);
            STRICT_EXPECTED_CALL(SSL_connect(IGNORED_PTR_ARG)).IgnoreArgument(1);
            STRICT_EXPECTED_CALL(SSL_get_error(IGNORED_PTR_ARG,IGNORED_NUM_ARG)).IgnoreArgument(1).IgnoreArgument(2);
            STRICT_EXPECTED_CALL(os_delay_us(IGNORED_NUM_ARG)).IgnoreArgument(1);
            retry++;
        }
        STRICT_EXPECTED_CALL(test_on_io_open_complete((void*)0x4242, IO_OPEN_ERROR));
        STRICT_EXPECTED_CALL(test_on_io_error((void*)0x4242));

        ///act
        result = tlsioInterfaces->concrete_io_open(&tls_io_instance, test_on_io_open_complete, (void*)0x4242, test_on_bytes_received, (void*)0x4242, test_on_io_error, (void*)0x4242);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_NOT_EQUAL(int, 0, result);

        ///cleanup
        if(g_ctx != NULL){
            free(g_ctx);
        }
        if (g_ssl != NULL){
            free(g_ssl);
        }
        if (g_sslmethod != NULL){
            free(g_sslmethod);
        }
    }

    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_012: [ If there is not enough memory to create the tlsio, the tlsio_openssl_create shall return NULL as the handle. ] */
    TEST_FUNCTION(tlsio_openssl_create_malloc__failed)
    {
        ///arrange
        OPTIONHANDLER_HANDLE result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;
        int negativeTestsInitResult = umock_c_negative_tests_init();
        size_t i;

        ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument(1);

        umock_c_negative_tests_snapshot();

        for (i = 0; i < umock_c_negative_tests_call_count(); i++)
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(i);
            ///act
            result = (OPTIONHANDLER_HANDLE)tlsioInterfaces->concrete_io_create((void*)&tlsio_config);

            ///assert
            ASSERT_IS_NULL(result);
        }

        ///cleanup
        umock_c_negative_tests_deinit();
    }


    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_009: [ The tlsio_openssl_create shall create a new instance of the tlsio for esp8266. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_010: [ The tlsio_openssl_create shall return a non-NULL handle on success. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_011: [ The tlsio_openssl_create shall allocate memory to control the tlsio instance. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_016: [ The tlsio_openssl_create shall initialize all callback pointers as NULL. ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_017: [ The tlsio_openssl_create shall receive the connection configuration (TLSIO_CONFIG). ] */
    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_020: [ If tlsio_openssl_create get success to create the tlsio instance, it shall set the tlsio state as TLSIO_STATE_NOT_OPEN. ] */
    TEST_FUNCTION(tlsio_openssl_create__succeed)
    {
        TLS_IO_INSTANCE* result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(gballoc_malloc(sizeof(TLS_IO_INSTANCE)));
        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(&g_destination, IGNORED_PTR_ARG)).IgnoreArgument(1).IgnoreArgument(2);

        ///act
        result = (TLS_IO_INSTANCE*)tlsioInterfaces->concrete_io_create((void*)&tlsio_config);

        ///assert
        ASSERT_IS_NOT_NULL(result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_EQUAL(int, (int)TLSIO_STATE_NOT_OPEN, result->tlsio_state);
        ///cleanup
        if (g_mallocptr != NULL){
            free(g_mallocptr);
        }
        if (g_destination != NULL){
            free(g_destination);
        }
    }


    /* TESTS_SRS_TLSIO_SSL_ESP8266_99_013: [ The tlsio_openssl_create shall return NULL when io_create_parameters is NULL. ] */
    TEST_FUNCTION(tlsio_openssl_create_NULL_parameters__failed)
    {
        ///arrange
        OPTIONHANDLER_HANDLE result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///act
        result = (OPTIONHANDLER_HANDLE)tlsioInterfaces->concrete_io_create(NULL);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_IS_NULL(result);

        ///cleanup
    }


    /* Tests_SRS_TLSIO_SSL_ESP8266_99_078: [ The tlsio_openssl_retrieveoptions shall not do anything, and return NULL. ]*/
    TEST_FUNCTION(tlsio_openssl_retrieveoptions__succeed)
    {
        ///arrange
        OPTIONHANDLER_HANDLE result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();

        ///act
        result = tlsioInterfaces->concrete_io_retrieveoptions(NULL);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_IS_NULL(result);

        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_077: [ he tlsio_openssl_setoption shall not do anything, and return 0. ]*/
    TEST_FUNCTION(tlsio_openssl_setoption__succeed)
    {
        ///arrange
        int result;
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces = tlsio_openssl_get_interface_description();
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        umock_c_reset_all_calls();

        ///act
        result = tlsioInterfaces->concrete_io_setoption(NULL, NULL, NULL);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
        ASSERT_ARE_EQUAL(int, 0, result);

        ///cleanup
    }

    /* Tests_SRS_TLSIO_SSL_ESP8266_99_008: [ The tlsio_openssl_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
    TEST_FUNCTION(tlsio_openssl_get_interface_description__succeed)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsioInterfaces;

        ///act
        tlsioInterfaces = tlsio_openssl_get_interface_description();

        ///assert
        ASSERT_IS_NOT_NULL(tlsioInterfaces);

        ///cleanup
    }


END_TEST_SUITE(tlsio_esp8266_ut)