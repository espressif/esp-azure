// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef _ESP8266_MOCK_H_
#define _ESP8266_MOCK_H_

#include <stdint.h>
#include "umock_c/umock_c_prod.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void SSL;
typedef void SSL_CTX;
typedef void SSL_METHOD;

/*
 * SSL_CTX_new - create a SSL context
 *
 * @param method - the SSL context configuration file
 *
 * @return the context point, if create failed return NULL
 */
//SSL_CTX* SSL_CTX_new(SSL_METHOD *method);
MOCKABLE_FUNCTION(, SSL_CTX*, SSL_CTX_new, SSL_METHOD*, method);


/*
 * SSL_CTX_free - free a SSL context
 *
 * @param method - the SSL context point
 *
 * @return none
 */
//void SSL_CTX_free(SSL_CTX *ctx);
MOCKABLE_FUNCTION(, void, SSL_CTX_free, SSL_CTX*, ctx);

/*
 * SSL_new - create a SSL
 *
 * @param ssl_ctx - the SSL context which includes the SSL parameter
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
//SSL* SSL_new(SSL_CTX *ssl_ctx);
MOCKABLE_FUNCTION(, SSL*, SSL_new, SSL_CTX*, ssl_ctx);

/*
 * SSL_free - free the SSL
 *
 * @param ssl - the SSL point which has been "SSL_new"
 *
 * @return none
 */
//void SSL_free(SSL *ssl);
MOCKABLE_FUNCTION(, void, SSL_free, SSL*, ssl);

/*
 * SSL_connect - connect to the remote SSL server
 *
 * @param ssl - the SSL point which has been "SSL_new"
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you can see the mbedtls error code
 */
//int SSL_connect(SSL *ssl);
MOCKABLE_FUNCTION(, int, SSL_connect, SSL*, ssl);

/*
 * SSL_read - read data from remote
 *
 * @param ssl - the SSL point which has been connected
 * @param buffer - the received data point
 * @param len - the received data length
 *
 * @return the result
 *     result > 0 : the length of the received data
 *     result = 0 : the connect is closed
 *     result < 0 : error, you can see the mbedtls error code
 */
// int SSL_read(SSL *ssl, void *buffer, int len);
MOCKABLE_FUNCTION(, int, SSL_read, SSL*, ssl, void*, buffer, int, len);

/*
 * SSL_write - send the data to remote
 *
 * @param ssl - the SSL point which has been connected
 * @param buffer - the send data point
 * @param len - the send data length
 *
 * @return the result of verifying
 *     result > 0 : the length of the written data
 *     result = 0 : the connect is closed
 *     result < 0 : error, you can see the mbedtls error code
 */
//int SSL_write(SSL *ssl, const void *buffer, int len);
MOCKABLE_FUNCTION(, int, SSL_write, SSL*, ssl, const void*, buffer, int, len);

/*
 * SSL_shutdown - shutdown the connection to the remote
 *
 * @param ssl - the SSL point which has been connected or accepted
 *
 * @return the result
 *     result = 0 : successfully
 *     result < 0 : error, you may see the mbedtls error code
 */
//int SSL_shutdown(SSL *ssl);
MOCKABLE_FUNCTION(, int, SSL_shutdown, SSL*, ssl);

/*
 * SSL_set_fd - set the socket file description to the SSL
 *
 * @param ssl - the SSL point which has been "SSL_new"
 * @param fd  - socket file description
 *
 * @return the result
 *     result = 1  : successfully
 *     result <= 0 : error, SSL is NULL or socket file description is NULL
 */
//int SSL_set_fd(SSL *ssl, int fd);
MOCKABLE_FUNCTION(, int, SSL_set_fd, SSL*, ssl, int, fd);

/*
 * TLSv1_client_method - create the target SSL context client method
 *
 * @return the TLSV1.0 version SSL context client method
 */
//SSL_METHOD* TLSv1_client_method(void);
MOCKABLE_FUNCTION(, SSL_METHOD*, TLSv1_client_method);

/**
 * @brief set the SSL context read buffer length
 *
 * @param ctx - SSL context point
 * @param len - read buffer length
 *
 * @return none
 */
//void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len);
MOCKABLE_FUNCTION(, void, SSL_CTX_set_default_read_buffer_len, SSL_CTX*, ctx, size_t, len);

/**
 * @brief get SSL error code
 *
 * @param ssl       - SSL point
 * @param ret_code  - SSL return code
 *
 * @return SSL error number
 */
//int SSL_get_error(const SSL *ssl, int ret_code);
MOCKABLE_FUNCTION(, int, SSL_get_error, const SSL*, ssl, int, ret_code);

#define MEMP_NUM_NETCONN                10


typedef uint32_t u32_t;
#define socklen_t unsigned int
typedef uint8_t u8_t;
typedef uint8_t uint8;
typedef uint16_t u16_t;
typedef int32_t err_t;

struct ip_addr {
  u32_t addr;
};
typedef struct ip_addr ip_addr_t;

#define SOL_SOCKET   0xfff     /* options for socket level */
#define SO_SNDBUF    0x1001    /* Unimplemented: send buffer size */
#define SO_RCVBUF    0x1002    /* receive buffer size */
#define SO_SNDLOWAT  0x1003    /* Unimplemented: send low-water mark */
#define SO_RCVLOWAT  0x1004    /* Unimplemented: receive low-water mark */
#define SO_SNDTIMEO  0x1005    /* Unimplemented: send timeout */
#define SO_RCVTIMEO  0x1006    /* receive timeout */
#define SO_ERROR     0x1007    /* get error status and clear */
#define SO_TYPE      0x1008    /* get socket type */
#define SO_CONTIMEO  0x1009    /* Unimplemented: connect timeout */
#define SO_NO_CHECK  0x100a    /* don't create UDP checksum */
#define SO_REUSEADDR 1         /* Enable address reuse */

#define  SO_KEEPALIVE   0x0008 /* keep connections alive */
#define IPPROTO_TCP     6
#define TCP_KEEPALIVE  0x02    /* send KEEPALIVE probes when idle for pcb->keep_idle milliseconds */
#define TCP_KEEPIDLE   0x03    /* set pcb->keep_idle  - Same as TCP_KEEPALIVE, but use seconds for get/setsockopt */
#define TCP_KEEPINTVL  0x04    /* set pcb->keep_intvl - Use seconds for get/setsockopt */
#define TCP_KEEPCNT    0x05    /* set pcb->keep_cnt   - Use number of probes sent for get/setsockopt */
#define SSL_ERROR_WANT_READ             2
#define SSL_ERROR_WANT_WRITE            3

#define AF_INET         2
/* Socket protocol types (TCP/UDP/RAW) */
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

int ioctl(int s, long cmd, void *argp);
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK  1 /* nonblocking I/O */
#define O_NDELAY    1 /* same as O_NONBLOCK, for compatibility */
#define LOCAL



typedef u8_t sa_family_t;
typedef u16_t in_port_t;

typedef u32_t in_addr_t;

struct in_addr {
  in_addr_t s_addr;
};


struct sockaddr_in {
  u8_t            sin_len;
  sa_family_t     sin_family;
  in_port_t       sin_port;
  struct in_addr  sin_addr;
#define SIN_ZERO_LEN 8
  char            sin_zero[SIN_ZERO_LEN];
};


struct sockaddr {
  u8_t        sa_len;
  sa_family_t sa_family;
#if LWIP_IPV6
  char        sa_data[22];
#else /* LWIP_IPV6 */
  char        sa_data[14];
#endif /* LWIP_IPV6 */
};

/* FD_SET used for lwip_select */
//int my_FD_ISSET(int n, void* p);
#ifndef FD_SET
  #undef  FD_SETSIZE
  /* Make FD_SETSIZE match NUM_SOCKETS in socket.c */
  #define FD_SETSIZE    MEMP_NUM_NETCONN
  #define FD_SET(n, p)  ((p)->fd_bits[(n)/8] |=  (1 << ((n) & 7)))
  #define FD_CLR(n, p)  ((p)->fd_bits[(n)/8] &= ~(1 << ((n) & 7)))
  //#define FD_ISSET(n,p) my_FD_ISSET(n, p)
  //((p)->fd_bits[(n)/8] &   (1 << ((n) & 7)))
  #define FD_ZERO(p)    memset((void*)(p),0,sizeof(*(p)))

  typedef struct fd_set {
          unsigned char fd_bits [(FD_SETSIZE+7)/8];
        } fd_set;

#endif /* FD_SET */

struct timeval {
  long    tv_sec;         /* seconds */
  long    tv_usec;        /* and microseconds */
};

//err_t netconn_gethostbyname(const char *name, ip_addr_t *addr);
MOCKABLE_FUNCTION(, err_t, netconn_gethostbyname, const char*, name, ip_addr_t*, addr);

//int socket(int domain, int type, int protocol);
MOCKABLE_FUNCTION(, int, socket, int, domain, int, type, int, protocol);

//int bind(int s, const struct sockaddr* name, socklen_t namelen);
MOCKABLE_FUNCTION(, int, bind, int, s, const struct sockaddr*, name, socklen_t, namelen);

//int connect(int s, const struct sockaddr *name, socklen_t namelen);
MOCKABLE_FUNCTION(, int, connect, int, s, const struct sockaddr*, name, socklen_t, namelen);

//int lwip_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
MOCKABLE_FUNCTION(, int, getsockopt, int, s, int, level, int, optname, void*, optval, socklen_t*, optlen);

//int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
//                struct timeval *timeout);
MOCKABLE_FUNCTION(, int, lwip_select, int, maxfdp1, fd_set*, readset, fd_set*, writeset, fd_set*, exceptset, struct timeval*, timeout);

//os_delay_us(int us);
MOCKABLE_FUNCTION(, void, os_delay_us, int, us);

//int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
MOCKABLE_FUNCTION(, int, setsockopt, int, s, int, level, int, optname, const void*, optval, socklen_t, optlen);

//int close(int s)
MOCKABLE_FUNCTION(, int, close, int, s);

MOCKABLE_FUNCTION(, int, FD_ISSET, int, n, void*, p);

//int fcntl(int s, int cmd, int val);
MOCKABLE_FUNCTION(, int, fcntl, int, s, int, cmd, int, val);


#define htons(x) (x)
#define ntohs(x) (x)
#define htonl(x) (x)
#define ntohl(x) (x)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
