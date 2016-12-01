#include "../header/sysheads.h"
#include "../header/common_head.h"

const int CA_MAX_LISTEN_LIMIT = 50;
int MAX_OPEN_FD = -1;

string_t CA_CONF_FILENAME = "../temp/openssl-ca.cnf";
const string_t CA_CONF =
"HOME            = .\n"
"RANDFILE        = $ENV::HOME/.rnd\n"
"\n"
"[ ca ]\n"
"default_ca  = CA_default\n"
"\n"
"[ CA_default ]\n"
"\n"
"base_dir    = ../auth/ca\n"
"certificate = $base_dir/ca_cert.pem\n"
"private_key = $base_dir/ca_key.pem\n"
"new_certs_dir   = $base_dir\n"
"database    = $base_dir/index.txt\n"
"serial      = $base_dir/serial.txt\n"
"\n"
"unique_subject  = no\n"
"\n"
"default_days    = 1000\n"
"default_crl_days= 30\n"
"default_md  = sha256\n"
"preserve    = no\n"
"\n"
"x509_extensions = ca_extensions\n"
"\n"
"email_in_dn = no\n"
"copy_extensions = copy\n"
"\n"
"[ req ]\n"
"default_bits        = 4096\n"
"default_keyfile     = ca_key.pem\n"
"distinguished_name  = ca_distinguished_name\n"
"x509_extensions     = ca_extensions\n"
"string_mask         = utf8only\n"
"\n"
"[ ca_distinguished_name ]\n"
"countryName         = Country Name (2 letter code)\n"
"countryName_default     = US\n"
"\n"
"stateOrProvinceName     = State or Province Name (full name)\n"
"stateOrProvinceName_default = Maryland\n"
"\n"
"localityName            = Locality Name (eg, city)\n"
"localityName_default        = Baltimore\n"
"\n"
"organizationName            = Organization Name (eg, company)\n"
"organizationName_default    = Test CA, Limited\n"
"\n"
"organizationalUnitName  = Organizational Unit (eg, division)\n"
"organizationalUnitName_default  = Server Research Department\n"
"\n"
"commonName          = Common Name (e.g. server FQDN or YOUR name)\n"
"commonName_default      = Test CA\n"
"\n"
"emailAddress            = Email Address\n"
"emailAddress_default        = test@example.com\n"
"\n"
"[ ca_extensions ]\n"
"\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid:always, issuer\n"
"basicConstraints = critical, CA:true\n"
"keyUsage = keyCertSign, cRLSign\n"
"\n"
"[ signing_policy ]\n"
"countryName     = optional\n"
"stateOrProvinceName = optional\n"
"localityName        = optional\n"
"organizationName    = optional\n"
"organizationalUnitName  = optional\n"
"commonName      = supplied\n"
"emailAddress        = optional\n"
"\n"
"[ signing_req ]\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid,issuer\n"
"\n"
"basicConstraints = CA:FALSE\n"
"keyUsage = digitalSignature, keyEncipherment";

using namespace std;

void setup_ca_server (fd_t &fd)
{
	sockaddr_in ca_sock;
	int rc;

	// Create Registration Socket
	fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, fd);	

	// Initialize Socket
	bzero ((char *)(&ca_sock), sizeof (ca_sock));

	ca_sock.sin_family = AF_INET;
	ca_sock.sin_port = htons (CA_PORT_NUM);
	inet_pton (AF_INET , CA_IPv4_ADDR.c_str(), &(ca_sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (fd, (sockaddr *)(&ca_sock), sizeof (ca_sock));
	assert (rc >= 0);

	// Listen on the ports for incoming connections
	rc = listen (fd, CA_MAX_LISTEN_LIMIT);
	assert (rc >= 0);

	cout << "INFO " << "@setup_ca_server: " << "CA listening for connection @port:" << CA_PORT_NUM << endl;
}

int main()
{
	signal (SIGINT, sigint_handler);
	signal (SIGSEGV, sigint_handler);
	signal (SIGABRT, sigint_handler);

	overwrite_file (CA_CONF_FILENAME, CA_CONF);

	fd_t ca_sockfd;	
	setup_ca_server (ca_sockfd);
	assert (ca_sockfd >= 0);

	int client_fd;

	while (true)
	{
		client_fd = 0;
		client_fd = accept (ca_sockfd, NULL, NULL);
		assert (client_fd >= 0);
		MAX_OPEN_FD = max (MAX_OPEN_FD, client_fd);

		cout << "INFO " << "@ca_main: " << "Accepted a CSR connection" << endl;
		send_positive_ACK (client_fd, "Connection Accepted. Client OK to Send CSR.");

		vector_string_t request_vector;
		recv_composed_message (client_fd, request_vector);

		switch (const_maps::MSG_TYPE_MAP[request_vector[1]])
		{
			case const_enums::CMD:
			{	switch (const_maps::CMD_TYPE_MAP[request_vector[2]])
				{
					case const_enums::CSR:
					{
						// SOH,CMD,CSR,uname,<.csr_file>,EOH
						string_t uname = request_vector[3];
						string_t csr_filename = "../temp/temp_" + uname + "_csr.csr";
						overwrite_file (csr_filename, request_vector[4]);

						string_t cert_filename = "../temp/temp_" + uname + "_cert.pem";
						string_t sign_command = 
							"openssl ca -key gursimran -config " + CA_CONF_FILENAME + " -policy signing_policy -extensions signing_req -out " + cert_filename +
							" -infiles " + csr_filename;
						system (sign_command.c_str());

						string_t cert_file;
						read_file (cert_filename, cert_file);
						send_composed_message (client_fd, const_enums::CMD, const_enums::SIGNED_CERT, cert_file);

						remove (csr_filename.c_str());
						remove (cert_filename.c_str());

						break;
					}
					default:
					{
						send_negative_ACK (client_fd, "Invalid Command for ca socket.");
						break;
					}
				}
				break;
			}
			default:
			{
				send_negative_ACK (client_fd, "Invalid Message Type for ca socket.");
				break;
			}
		}

		close_fd (client_fd);
	}

	return 0;
}