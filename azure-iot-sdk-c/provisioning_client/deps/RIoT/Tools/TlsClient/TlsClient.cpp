// RIoTOsslClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

/*
	This test utility is derived from the sample code at
	https://wiki.openssl.org/index.php/SSL/TLS_Client 

	The only substantive changes are marked <PAUL></PAUL>

*/


int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
void init_openssl_library(void);
void print_cn_name(const char* label, X509_NAME* const name);
void print_san_name(const char* label, X509* const cert);
void print_error_string(unsigned long err, const char* const label);
void CheckIsOne(unsigned long err, const char* const label);
void CheckIsNotNull(void* p, const char* const label);
int  Usage();

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

int main(int argc, char* argv[])
{
	BOOL useChain;
	char dir[128], deviceCertChain[128], aliasKey[128], serverCA[128], aliasCert[128];;
	
	if (argc == 1) return Usage();
	if (argc > 3)return Usage();

	if (strcmp(argv[1], "B") == 0)
	{
		useChain = FALSE;
	}
	else
		if (strcmp(argv[1], "C")==0)
		{
			useChain = TRUE;
		}
		else
			return Usage();

	if (argc == 3) 
	{
		strcpy(dir, argv[2]);
	}
	else
	{
		strcpy(dir, ".");
	}

	//strcat(dir, "/");

	strcpy(aliasKey, dir);			strcat(aliasKey, "AliasKey.PEM");
	strcpy(deviceCertChain, dir);	strcat(deviceCertChain, "DeviceCertChainIncAlias.PEM");
	strcpy(serverCA, dir);			strcat(serverCA, "ServerCA.PEM");
	strcpy(aliasCert, dir);			strcat(aliasCert, "AliasCert.PEM");

	printf("Attempting to establish a TLS connection on localhost\n");


	long res = 1;
	int ret = 1;
	unsigned long ssl_err = 0;

	SSL_CTX* ctx = NULL;
	BIO *web = NULL, *out = NULL;
	SSL *ssl = NULL;

	do {
		// for interactive debugging
		Sleep(3000);

		init_openssl_library();
		const SSL_METHOD* method = SSLv23_method();
		CheckIsNotNull((void*) method, "SSLv23_method");

		ctx = SSL_CTX_new(method);
		CheckIsNotNull((void*)ctx, "SSL_CTX_new");

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
		SSL_CTX_set_verify_depth(ctx, 10);


		/* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
		/* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
		/* and above. An added benefit of TLS 1.0 and above are TLS          */
		/* extensions like Server Name Indicatior (SNI).                     */
		const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		long old_opts = SSL_CTX_set_options(ctx, flags);
		UNUSED(old_opts);

		// <PAUL> - the following three setup lines are the only substantive changes to the 
		// OSSL sample code
		res = SSL_CTX_use_PrivateKey_file(ctx, aliasKey, SSL_FILETYPE_PEM);
		CheckIsOne(res, "SSL_CTX_use_PrivateKey_file");
		if (useChain) 
		{
			res = SSL_CTX_use_certificate_chain_file(ctx, deviceCertChain);
			CheckIsOne(res, "SSL_CTX_use_certificate_chain_file");
		}
		else
		{
			res = SSL_CTX_use_certificate_chain_file(ctx, aliasCert);
			CheckIsOne(res, "SSL_CTX_use_certificate_chain_file");
		}
		res = SSL_CTX_load_verify_locations(ctx, serverCA, NULL);
		CheckIsOne(res, "SSL_CTX_load_verify_locations");
		// </PAUL>


		web = BIO_new_ssl_connect(ctx);
		CheckIsNotNull((void*)web, "BIO_new_ssl_connect");
		res = BIO_set_conn_hostname(web, "localhost:5556");
		CheckIsOne(res, "BIO_set_conn_hostname");
		BIO_get_ssl(web, &ssl);
		res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
		CheckIsOne(res, "SSL_set_cipher_list");
		res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
		CheckIsOne(res, "SSL_set_tlsext_host_name");
		res = BIO_do_connect(web);
		CheckIsOne(res, "BIO_do_connect");
		res = BIO_do_handshake(web);
		CheckIsOne(res, "BIO_do_handshake");


		X509* cert = SSL_get_peer_certificate(ssl);
		if (cert) { X509_free(cert); } /* Free immediately */
		CheckIsNotNull(cert, "SSL_get_peer_certificate");
		/* Error codes: http://www.openssl.org/docs/apps/verify.html  */
		res = SSL_get_verify_result(ssl);

		ASSERT(X509_V_OK == res);
		if (!(X509_V_OK == res))
		{
			/* Hack a code into print_error_string. */
			print_error_string((unsigned long)res, "SSL_get_verify_results");
			break; /* failed */
		}



		/* Step 3: hostname verifcation.   */
		/* An exercise left to the reader. */

		/**************************************************************************************/
		/**************************************************************************************/
		/* Now, we can finally start reading and writing to the BIO...                        */
		/**************************************************************************************/
		/**************************************************************************************/

		printf("Connection was successful.  Terminating");


		BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\nHost: " HOST_NAME "\r\nConnection: close\r\n\r\n");
		BIO_puts(out, "\nFetching: " HOST_RESOURCE "\n\n");

#ifdef USE_CONNECTION
		int len = 0;
		do {
			char buff[1536] = {};

			/* https://www.openssl.org/docs/crypto/BIO_read.html */
			len = BIO_read(web, buff, sizeof(buff));

			if (len > 0)
				BIO_write(out, buff, len);

			/* BIO_should_retry returns TRUE unless there's an  */
			/* error. We expect an error when the server        */
			/* provides the response and closes the connection. */

		} while (len > 0 || BIO_should_retry(web));
#endif

		ret = 0;

	} while (0);

	if (out)
		BIO_free(out);

	if (web != NULL)
		BIO_free_all(web);

	if (NULL != ctx)
		SSL_CTX_free(ctx);

	// for interactive debugging
	Sleep(3000);


	return ret;
}

void init_openssl_library(void)
{
	/* https://www.openssl.org/docs/ssl/SSL_library_init.html */
	(void)SSL_library_init();
	/* Cannot fail (always returns success) ??? */

	/* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
	SSL_load_error_strings();
	/* Cannot fail ??? */

	/* SSL_load_error_strings loads both libssl and libcrypto strings */
	/* ERR_load_crypto_strings(); */
	/* Cannot fail ??? */

	/* OpenSSL_config may or may not be called internally, based on */
	/*  some #defines and internal gyrations. Explicitly call it    */
	/*  *IF* you need something from openssl.cfg, such as a         */
	/*  dynamically configured ENGINE.                              */
	OPENSSL_config(NULL);
	/* Cannot fail ??? */

	/* Include <openssl/opensslconf.h> to get this define     */
#if defined (OPENSSL_THREADS)
	/* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO */
	/* https://www.openssl.org/docs/crypto/threads.html */
	fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

void print_cn_name(const char* label, X509_NAME* const name)
{
	int idx = -1, success = 0;
	unsigned char *utf8 = NULL;

	do
	{
		if (!name) break; /* failed */

		idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
		if (!(idx > -1))  break; /* failed */

		X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
		if (!entry) break; /* failed */

		ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
		if (!data) break; /* failed */

		int length = ASN1_STRING_to_UTF8(&utf8, data);
		if (!utf8 || !(length > 0))  break; /* failed */

		fprintf(stdout, "  %s: %s\n", label, utf8);
		success = 1;

	} while (0);

	if (utf8)
		OPENSSL_free(utf8);

	if (!success)
		fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
	int success = 0;
	GENERAL_NAMES* names = NULL;
	unsigned char* utf8 = NULL;

	do
	{
		if (!cert) break; /* failed */

		names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
		if (!names) break;

		int i = 0, count = sk_GENERAL_NAME_num(names);
		if (!count) break; /* failed */

		for (i = 0; i < count; ++i)
		{
			GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
			if (!entry) continue;

			if (GEN_DNS == entry->type)
			{
				int len1 = 0, len2 = -1;

				len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
				if (utf8) {
					len2 = (int)strlen((const char*)utf8);
				}

				if (len1 != len2) {
					fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
				}

				/* If there's a problem with string lengths, then     */
				/* we skip the candidate and move on to the next.     */
				/* Another policy would be to fails since it probably */
				/* indicates the client is under attack.              */
				if (utf8 && len1 && len2 && (len1 == len2)) {
					fprintf(stdout, "  %s: %s\n", label, utf8);
					success = 1;
				}

				if (utf8) {
					OPENSSL_free(utf8), utf8 = NULL;
				}
			}
			else
			{
				fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
			}
		}

	} while (0);

	if (names)
		GENERAL_NAMES_free(names);

	if (utf8)
		OPENSSL_free(utf8);

	if (!success)
		fprintf(stdout, "  %s: <not available>\n", label);

}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
	/* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err = X509_STORE_CTX_get_error(x509_ctx);

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
	X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

	fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

	/* Issuer is the authority we trust that warrants nothing useful */
	print_cn_name("Issuer (cn)", iname);

	/* Subject is who the certificate is issued to by the authority  */
	print_cn_name("Subject (cn)", sname);

	if (depth == 0) {
		/* If depth is 0, its the server's certificate. Print the SANs */
		print_san_name("Subject (san)", cert);
	}

	if (preverify == 0)
	{
		if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
			fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
		else if (err == X509_V_ERR_CERT_UNTRUSTED)
			fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
		else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
			fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
		else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
			fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
		else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
			fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
		else if (err == X509_V_OK)
			fprintf(stdout, "  Error = X509_V_OK\n");
		else
			fprintf(stdout, "  Error = %d\n", err);
	}

#if !defined(NDEBUG)
	return 1;
#else
	return preverify;
#endif
}

void print_error_string(unsigned long err, const char* const label)
{
	const char* const str = ERR_reason_error_string(err);
	if (str)
		fprintf(stderr, "%s\n", str);
	else
		fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);

	Sleep(3000);

}

void CheckIsOne(unsigned long err, const char* const label)
{
	if (err == 1)return;
	unsigned long ssl_err = ERR_get_error();
	fprintf(stderr, "(NotOne) Error number %d -- %s\n", ssl_err, label);
	Sleep(3000);
	exit(1);
}
void CheckIsNotNull(void* p, const char* const label)
{
	if (p != NULL)return;
	unsigned long ssl_err = ERR_get_error();
	fprintf(stderr, "(IsNull) Error number %d -- %s\n", ssl_err, label);
	Sleep(3000);
	exit(1);
}
int Usage()
{
	fprintf(stderr, "Usage: TlsClient [B|C]			Looks for PEM-encoded certificate files in current directory.");
	fprintf(stderr, "		TlsClient [B|C] dir		Looks for PEM-encoded certificate files in dir");
	fprintf(stderr, "				B - Use the bare alias certificate");
	fprintf(stderr, "				C - Use the device certificate chain");

	return 1;

}
