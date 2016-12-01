#include "./sysheads.h"
#include "./common_head.h"

const string_t CA_CERTFILE = "../auth/ca/ca_cert.pem";

void OpenListener (fd_t &fd, string_t ip_addr, int &port);
SSL_CTX* InitSSLCTX (int mode, string_t CLIENT_CERTFILE, string_t CLIENT_KEYFILE);
void LoadCertificates (SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowServerCerts (SSL* ssl);
void ShowClientCerts (SSL* ssl);
void OpenConnection (fd_t &connect_fd, string_t ip_addr, int port);

void SSL_send_positive_ACK (SSL *ssl, string_t description);
void SSL_send_negative_ACK (SSL *ssl, string_t description);
void recv_from_ssl (SSL *ssl, string_t response);
int SSL_recv_ACK (SSL *ssl);
void SSL_send_composed_message (SSL *ssl, const_enums::MessageType message_type, ...);
void SSL_recv_composed_message (SSL *ssl, vector_string_t &response_vector);