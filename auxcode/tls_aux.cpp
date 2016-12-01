#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/tls.h"

// Server

// #define FAIL -1

using namespace std;

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
/*
int OpenListener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}
*/

void OpenListener (fd_t &fd, string_t ip_addr, int &port)
{
	sockaddr_in sock;
	int rc;

	// Create Registration Socket
	fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, fd);	

	// Initialize Socket
	bzero ((char *)(&sock), sizeof (sock));

	sock.sin_family = AF_INET;
	sock.sin_port = 0;			// auto-assign
	inet_pton (AF_INET , ip_addr.c_str(), &(sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (fd, (sockaddr *)(&sock), sizeof (sock));
	assert (rc >= 0);

	bzero ((char *)(&sock), sizeof (sock));
	socklen_t len = sizeof (sock);
	if (getsockname(fd, (struct sockaddr *) &sock, &len) == -1) {
		return;
	}

	port = ntohs (sock.sin_port);

	// Listen on the ports for incoming connections
	rc = listen (fd, 1);
	assert (rc >= 0);

	cout << "INFO " << "@openListener: " << "Client listening for connection requests @port:" << port << endl;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitSSLCTX (int mode, string_t CLIENT_CERTFILE, string_t CLIENT_KEYFILE)
{
	OpenSSL_add_ssl_algorithms();
	OpenSSL_add_all_algorithms();        /* load & register all cryptos, etc. */
	SSL_load_error_strings();            /* load all error messages */

	SSL_CTX *ctx;
	const SSL_METHOD *method;

	if (mode == 1) {
		method = SSLv23_server_method();
	}
	else if (mode == 2) {
		method = SSLv23_client_method();
	}

	ctx = SSL_CTX_new (method);          /* create new context from method */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (mode == 1) {
		SSL_CTX *sslctx = SSL_CTX_new (SSLv23_server_method());
		SSL_CTX_use_certificate_file (sslctx, (char *)CA_CERTFILE.c_str(), SSL_FILETYPE_PEM);
		SSL *ssl = SSL_new (sslctx);
		X509 *crt = SSL_get_certificate (ssl);

		SSL_CTX_add_client_CA (ctx, crt);
		SSL_CTX_load_verify_locations (ctx, (char *)CA_CERTFILE.c_str(), NULL);
	}
	else if (mode == 2) {
		SSL_CTX *sslctx = SSL_CTX_new (SSLv23_client_method());
		SSL_CTX_use_certificate_file (sslctx, (char *)CA_CERTFILE.c_str(), SSL_FILETYPE_PEM);
		SSL *ssl = SSL_new (sslctx);
		X509 *crt = SSL_get_certificate (ssl);

		SSL_CTX_add_client_CA (ctx, crt);
		SSL_CTX_load_verify_locations (ctx, (char *)CA_CERTFILE.c_str(), NULL);
	}

	// Do all configueration of context here only
	LoadCertificates (ctx, (char *)CLIENT_CERTFILE.c_str(), (char *)CLIENT_KEYFILE.c_str());
	SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(ctx, flags);

	return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates (SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowServerCerts (SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);   /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void ShowClientCerts (SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);   /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Client certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
// void Servlet(SSL* ssl)  /* Serve the connection -- threadable */
// {
// 	char buf[1024];
// 	char reply[1024];
// 	int sd, bytes;
// 	const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

// 	if ( SSL_accept(ssl) == FAIL )                  /* do SSL-protocol accept */
// 	ERR_print_errors_fp(stderr);
// 	else
// 	{
// 	ShowCerts(ssl);                             /* get any certificates */
// 	bytes = SSL_read(ssl, buf, sizeof(buf));    /* get request */
// 		if ( bytes > 0 )
// 		{
// 			buf[bytes] = 0;
// 			printf("Client msg: \"%s\"\n", buf);
// 			sprintf(reply, HTMLecho, buf);          /* construct reply */
// 			SSL_write(ssl, reply, strlen(reply));   /* send reply */
// 		}
// 		else
// 			ERR_print_errors_fp(stderr);
// 	}
// 	sd = SSL_get_fd(ssl);                           /* get socket connection */
// 	SSL_free(ssl);                                  /* release SSL state */
// 	close(sd);                                      /* close connection */
// }

/*---------------------------------------------------------------------*/
/*--- main - create SSL socket server.                              ---*/
/*---------------------------------------------------------------------*/
// int main(int count, char *strings[])
// {   SSL_CTX *ctx;
//     int server;
//     char *portnum;

//     if ( count != 2 )
//     {
//         printf("Usage: %s <portnum>\n", strings[0]);
//         exit(0);
//     }
//     portnum = strings[1];
//     ctx = InitServerCTX();                              /* initialize SSL */
//     LoadCertificates(ctx, (char*)"server_cert.pem", (char*)"server_key.pem");   /* load certs */
//     server = OpenListener(atoi(portnum));               /* create server socket */
//     while (1)
//     {   struct sockaddr_in addr;
//         int len = sizeof(addr);
//         SSL *ssl;

//         int client = accept(server, (struct sockaddr *)&addr, (socklen_t*)&len);        /* accept connection as usual */
//         printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
//         ssl = SSL_new(ctx);                             /* get new SSL state with context */
//         SSL_set_fd(ssl, client);                        /* set connection socket to SSL state */
//         Servlet(ssl);                                   /* service connection */
//     }
//     close(server);                                      /* close server socket */
//     SSL_CTX_free(ctx);                                  /* release context */
// }


// Client

/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
// int OpenConnection(const char *hostname, int port)
// {
// 	int sd;
// 	struct hostent *host;
// 	struct sockaddr_in addr;

// 	if ( (host = gethostbyname(hostname)) == NULL )
// 	{
// 		perror(hostname);
// 		abort();
// 	}
// 	sd = socket(PF_INET, SOCK_STREAM, 0);
// 	bzero(&addr, sizeof(addr));
// 	addr.sin_family = AF_INET;
// 	addr.sin_port = htons(port);
// 	addr.sin_addr.s_addr = *(long*)(host->h_addr);
// 	if ( connect(sd, (const sockaddr*)&addr, sizeof(addr)) != 0 )
// 	{
// 		close(sd);
// 		perror(hostname);
// 		abort();
// 	}
// 	return sd;
// }

void OpenConnection (fd_t &connect_fd, string_t ip_addr, int port)
{
	sockaddr_in sock;
	int rc;

	connect_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (connect_fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, connect_fd);	

	bzero ((char *) &sock, sizeof (sock));
	sock.sin_family = AF_INET;
	sock.sin_port = htons (port);
	rc = inet_pton (AF_INET, ip_addr.c_str(), &(sock.sin_addr));
	assert (rc == 1);

	rc = connect (connect_fd, (sockaddr *) &sock, sizeof (sock));
	assert (rc == 0);
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
// int main(int count, char *strings[])
// {   SSL_CTX *ctx;
//     int server;
//     SSL *ssl;
//     char buf[1024];
//     int bytes;
//     char *hostname, *portnum;

//     if ( count != 3 )
//     {
//         printf("usage: %s <hostname> <portnum>\n", strings[0]);
//         exit(0);
//     }
//     hostname=strings[1];
//     portnum=strings[2];

//     ctx = InitCTX();
//     LoadCertificates(ctx, (char*)"cli_cert.pem", (char*)"cli_key.pem");
//     server = OpenConnection(hostname, atoi(portnum));
//     ssl = SSL_new(ctx);                     /* create new SSL connection state */
//     SSL_set_fd(ssl, server);                /* attach the socket descriptor */
//     if ( SSL_connect(ssl) == FAIL )          perform the connection 
//         ERR_print_errors_fp(stderr);
//     else
//     {   char *msg = (char*)"Hello???";

//         printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
//         ShowCerts(ssl);                             /* get any certs */
//         SSL_write(ssl, msg, strlen(msg));           /* encrypt & send message */
//         bytes = SSL_read(ssl, buf, sizeof(buf));    /* get reply & decrypt */
//         buf[bytes] = 0;
//         printf("Received: \"%s\"\n", buf);
//         SSL_free(ssl);                              /* release connection state */
//     }
//     close(server);                                  /* close socket */
//     SSL_CTX_free(ctx);                              /* release context */
// }

// Some Modified function that now use SSL instead of FD


void SSL_send_composed_message (SSL *ssl, const_enums::MessageType message_type, ...)
{
	va_list vararg_list;
	vector_string_t out_command;

	out_command.clear ();
	out_command.push_back (CTRL_STR[0]);		// SOH
	
	assert (map_contains_value (const_maps::MSG_TYPE_MAP, message_type) == true);
	out_command.push_back
			(map_get_key_from_value (const_maps::MSG_TYPE_MAP, message_type));

	va_start (vararg_list, message_type);		// Initialize vararg_list

	int expected_args;
	string_t arg;

	switch (message_type)
	{
		case const_enums::CMD:
		{
			const_enums::CommandType command_type = (const_enums::CommandType) va_arg (vararg_list, int);
			assert (map_contains_value (const_maps::CMD_TYPE_MAP, command_type) == true);
			out_command.push_back
					(map_get_key_from_value (const_maps::CMD_TYPE_MAP, command_type));

			switch (command_type)
			{
				case const_enums::REG:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::LOG_IN:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::LOG_OUT:
				{
					expected_args = 0;
					break;
				}
				case const_enums::MSG:
				{
					expected_args = 3;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::CONNECT_REQUEST:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::CONNECT_RESPONSE:
				{
					expected_args = 4;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				default:
					return;
			}
			break;
		}
		case const_enums::ACK:
		{
			const_enums::AcknowledgementType ack_type = (const_enums::AcknowledgementType) va_arg (vararg_list, int);
			assert (map_contains_value (const_maps::ACK_TYPE_MAP, ack_type) == true);
			out_command.push_back
					(map_get_key_from_value (const_maps::ACK_TYPE_MAP, ack_type));

			switch (ack_type)
			{
				case const_enums::OK:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::ERR:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				default:
					return;
			}
			break;
		}
		default:
			return;
	}

	va_end (vararg_list);					// Cleanup list

	out_command.push_back (CTRL_STR[2]);	// EOT
	
	string_t out_command_string = join_message_vector (out_command);	
	string_t out_command_printable = join_message_vector (out_command, " | ");
	cout << "INFO " << "@SSL_send_composed_message: " << "Sending command:" << endl;
	cout << out_command_printable << endl;

	int rc = SSL_write (ssl, out_command_string.c_str(), out_command_string.size());
	assert (rc > 0);
}

void SSL_recv_composed_message (SSL *ssl, vector_string_t &response_vector)
{
	char buff[4000];
	int rc = SSL_read (ssl, buff, 4000);
	buff[rc] = 0;

	string_t read_response = buff;
	split_to_composed_message (read_response, response_vector);
	assert (response_vector.empty() == false);
}