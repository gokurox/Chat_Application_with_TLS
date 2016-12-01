#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/tls.h"
#include "../header/client_head.h"

using namespace std;

// Local Prototypes
void log_out_user (fd_t &, map_string_connection_t &);
void msg_user (fd_t &, map_string_connection_t &, const vector_string_t);
void connect_to_user (fd_t &, map_string_connection_t &, string_t);

void connect_to_signup_server (fd_t &signup_fd)
{
	sockaddr_in signup_sock;
	int rc;

	signup_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (signup_fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, signup_fd);	

	bzero ((char *) &signup_sock, sizeof (signup_sock));
	signup_sock.sin_family = AF_INET;
	signup_sock.sin_port = htons (SIGNUP_PORT_NUM);
	rc = inet_pton (AF_INET, SERVER_IPv4_ADDR.c_str(), &(signup_sock.sin_addr));
	assert (rc == 1);

	rc = connect (signup_fd, (sockaddr *) &signup_sock, sizeof (signup_sock));
	assert (rc == 0);
	cout << "INFO " << "@connect_to_signup_server: " << "Connected to server." << endl;

	rc = recv_ACK (signup_fd);
	assert (rc != 0);
}

void connect_to_signin_server (fd_t &signin_fd)
{
	sockaddr_in signin_sock;
	int rc;

	signin_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (signin_fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, signin_fd);	

	bzero ((char *) &signin_sock, sizeof (signin_sock));
	signin_sock.sin_family = AF_INET;
	signin_sock.sin_port = htons (SIGNIN_PORT_NUM);
	rc = inet_pton (AF_INET, SERVER_IPv4_ADDR.c_str(), &(signin_sock.sin_addr));
	assert (rc == 1);

	rc = connect (signin_fd, (sockaddr *) &signin_sock, sizeof (signin_sock));
	assert (rc == 0);
	cout << "INFO " << "@connect_to_signin_server: " << "Connected to server." << endl;

	rc = recv_ACK (signin_fd);
	assert (rc != 0);
}

void connect_to_ca (fd_t &ca_fd)
{
	sockaddr_in ca_sock;
	int rc;

	ca_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (ca_fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, ca_fd);	

	bzero ((char *) &ca_sock, sizeof (ca_sock));
	ca_sock.sin_family = AF_INET;
	ca_sock.sin_port = htons (CA_PORT_NUM);
	rc = inet_pton (AF_INET, CA_IPv4_ADDR.c_str(), &(ca_sock.sin_addr));
	assert (rc == 1);

	rc = connect (ca_fd, (sockaddr *) &ca_sock, sizeof (ca_sock));
	assert (rc == 0);
	cout << "INFO " << "@connect_to_ca: " << "Connected to ca." << endl;

	rc = recv_ACK (ca_fd);
	assert (rc != 0);
}

void process_signup_request (fd_t &fd, const vector_string_t client_signup_request)
{
	string_t username = client_signup_request[1];
	string_t password = client_signup_request[2];

	send_composed_message (fd, const_enums::CMD, const_enums::REG, username, password);
	recv_ACK (fd);

	close_fd (fd);
}

void process_signin_request (fd_t &serverfd, const vector_string_t client_signin_request)
{
	string_t username = client_signin_request[1];
	string_t password = client_signin_request[2];

	send_composed_message (serverfd, const_enums::CMD, const_enums::LOG_IN, username, password);
	int rc = recv_ACK (serverfd);
	assert (rc != 0);

	if (rc == 2) {
		cout << "WARNING " << "@process_signin_request: " << "Could not Sign In." << endl;
		return;
	}
	else {
		CLIENT_USERNAME = username;
		CLIENT_PASSWORD = password;
		CLIENT_IP_ADDR = "127.0.0.1";

		cout << endl;
		cout << "Please provide Certificate and Private Key File..." << endl;
		do 
		{
			char choice;
			cout << "FilePath(P)/Generate(G): ";
			cin >> choice;

			if (choice == 'G' || choice == 'g') {
				string_t cert_filename = "../temp/" + CLIENT_USERNAME + "_cert.pem";
				string_t csr_filename = "../temp/" + CLIENT_USERNAME + "_cert.csr";
				string_t key_filename = "../temp/" + CLIENT_USERNAME + "_key.pem";
				
				string_t csrgen_command =
					"openssl req -newkey rsa:4096 -sha256"
					" -out " + csr_filename +
					" -keyout " + key_filename + " -nodes -outform PEM";
				system (csrgen_command.c_str());

				fd_t conn_fd;
				connect_to_ca (conn_fd);

				string_t csr_file;
				read_file (csr_filename, csr_file);
				send_composed_message (conn_fd, const_enums::CMD, const_enums::CSR, CLIENT_USERNAME, csr_file);

				vector_string_t csr_response;
				recv_composed_message (conn_fd, csr_response);
				close_fd (conn_fd);

				remove (csr_filename.c_str());

				overwrite_file (cert_filename, csr_response[3]);

				CLIENT_CERTFILE = cert_filename;
				CLIENT_KEYFILE = key_filename;
			}

			if (choice == 'P' || choice == 'p') {
				cout << "Certificate Path: ";
				cin >> CLIENT_CERTFILE;
				if (!file_exists(CLIENT_CERTFILE)) {
					cout << "File does not exist.. Rebounding." << endl;
					CLIENT_CERTFILE.clear();
					continue;
				}

				cout << "Private Key Path: ";
				cin >> CLIENT_KEYFILE;
				if (!file_exists(CLIENT_KEYFILE)) {
					cout << "File does not exist.. Rebounding." << endl;
					CLIENT_KEYFILE.clear();
					continue;
				}
			}
		} while (CLIENT_CERTFILE.empty() || CLIENT_KEYFILE.empty());
	}

	fd_set sockfd_set;
	fd_t max_fd;
	map_string_fd_t openListeners;
	map_string_connection_t connected_users;

	char client_input[1025];
	bool break_loop = false;

	cin.get();		// Pause
	system ("clear");

	do {
		if (serverfd < 0)
			break;

		show_prompt ();

		// Clear the Socket Set
		FD_ZERO (&sockfd_set);

		FD_SET (fileno (stdin), &sockfd_set);
		FD_SET (serverfd, &sockfd_set);

		max_fd = max (serverfd, fileno (stdin));

		map_string_fd_t::iterator it1 = openListeners.begin();
		for (; it1 != openListeners.end(); it1++) {
			fd_t listen_fd = it1 -> second;
			if (listen_fd >= 0) {
				FD_SET (listen_fd, &sockfd_set);
				max_fd = max (listen_fd, max_fd);
			}
		}

		map_string_connection_t::iterator it2 = connected_users.begin();
		for (; it2 != connected_users.end(); it2++) {
			connection_data_t data = it2 -> second;
			if (data.conn_fd >= 0) {
				FD_SET (data.conn_fd, &sockfd_set);
				max_fd = max (data.conn_fd, max_fd);
			}
		}

		select (max_fd +1, &sockfd_set, NULL, NULL, NULL);

		if (FD_ISSET (serverfd, &sockfd_set))
		{
			vector_string_t server_request;
			recv_composed_message (serverfd, server_request);

			switch (const_maps::MSG_TYPE_MAP [server_request[1]])
			{
				case const_enums::CMD:
				{
					switch (const_maps::CMD_TYPE_MAP [server_request[2]])
					{
						case const_enums::CONNECT_REQUEST:
						{
							// SOH,CMD,CONNECT_REQ,FROM,TO,EOT

							if (server_request[4].compare(CLIENT_USERNAME) != 0)
								break;

							fd_t listen_fd;
							int listen_port;
							OpenListener (listen_fd, CLIENT_IP_ADDR, listen_port);
							assert (listen_fd >= 0);

							send_composed_message (serverfd, const_enums::CMD, const_enums::CONNECT_RESPONSE, CLIENT_USERNAME, server_request[3], CLIENT_IP_ADDR, integer_to_string(listen_port));

							openListeners[server_request[3]] = listen_fd;
							break;
						}
						default:
							break;
					}
					break;
				}
				case const_enums::ACK:
					break;
				case const_enums::CLOSE_CONN:
					close_fd (serverfd);
					break;
				default:
					break;
			}
		}

		map_string_fd_t::iterator it3 = openListeners.begin();
		for (; it3 != openListeners.end(); it3++) {
			fd_t listen_fd = it3 -> second;
			if (listen_fd >= 0) {
				if (FD_ISSET (listen_fd, &sockfd_set)) {
					fd_t conn_fd = accept (listen_fd, NULL, NULL);
					MAX_OPEN_FD = max (MAX_OPEN_FD, conn_fd);	

					connection_data_t data;
					data.username = it3 -> first;
					data.conn_fd = conn_fd;

					// TLS
					data.ctx = InitSSLCTX (1, CLIENT_CERTFILE, CLIENT_KEYFILE);
					data.ssl = SSL_new (data.ctx);
					SSL_set_fd (data.ssl, data.conn_fd);

					sleep (1);

					// TLS Handshake
					if (SSL_accept (data.ssl) == -1)					/* do SSL-protocol accept */
					{
						ERR_print_errors_fp (stderr);
					}
					else
					{
						int res = SSL_get_verify_result(data.ssl);
						if (X509_V_OK == res) {
							cout << "Certificate verified successfuly." << endl;
						}
						else {
							cout << "Certificate verification failed." << endl;
							return;
						}

						cout << "Connected with " << SSL_get_cipher (data.ssl) << " encryption" << endl;
						cout << endl;
						ShowClientCerts (data.ssl);								/* get any certificates */
						cout << endl;
					}

					connected_users[data.username] = data;
					close_fd (it3 -> second);
				}
			}
		}

		map_string_connection_t::iterator it4 = connected_users.begin();
		for (; it4 != connected_users.end(); it4++) {
			connection_data_t data = it4 -> second;
			if (data.conn_fd >= 0) {
				if (FD_ISSET (data.conn_fd, &sockfd_set))
				{
					vector_string_t server_request;
					SSL_recv_composed_message (data.ssl, server_request);

					switch (const_maps::MSG_TYPE_MAP [server_request[1]])
					{
						case const_enums::CMD:
						{
							switch (const_maps::CMD_TYPE_MAP [server_request[2]])
							{
								case const_enums::MSG:
								{
									cout << endl << endl;
									cout << "MESSAGE RECEIVED:" << endl;
									cout << "FROM: " << server_request[3] << endl;
									cout << "MESSAGE:" << endl;
									cout << server_request[5] << endl;
									cout << endl;

									break;
								}
								default:
									break;
							}
							break;
						}
						case const_enums::ACK:
							break;
						case const_enums::CLOSE_CONN:
							close_fd (data.conn_fd);
							break;
						default:
							break;
					}

					if (data.conn_fd == -1)
						(it4 -> second).conn_fd = -1;
				}
			}
		}

		if (FD_ISSET (fileno (stdin), &sockfd_set))
		{
			bzero (client_input, 1025);
			cin.getline (client_input, 1024);
			
			vector_string_t client_request;
			if (string_t (client_input).empty() == false) {
				split_message (client_input, " ", client_request);
			}
			else
			{
				cout << "Invalid command! Please type \"/help\" at the prompt to view valid commands." << endl;
				continue;
			}

			switch (client_const::CLIENT_INPUT_COMMAND_MAP[client_request[0]])
			{
				case client_const::clnt_register:
				case client_const::clnt_login:
				{
					cout << "INFO " << "@process_signin_request: " << "Logout to use this command." << endl;
					break;
				}
				case client_const::clnt_logout:
				{
					log_out_user (serverfd, connected_users);
					break_loop = true;
					break;
				}
				case client_const::clnt_msg:
				{
					if (client_request.size() != 2) {
						cout << "Invalid command! Please type \"/help\" at the prompt to view valid commands." << endl;
						cin.get();		// Pause
						break;
					}

					msg_user (serverfd, connected_users, client_request);
					break;
				}
				case client_const::clnt_help:
				{
					help ();
					break;
				}
				case client_const::clnt_exit:
				{
					cout << "INFO " << "@process_signin_request: " << "Logout first and then use '/exit'." << endl;
					break;
				}
				default:
				{
					cout << "WARNING " << "@process_signin_request: " << "Invalid command." << endl;
					break;
				}
			}
		}
	} while (break_loop == false);
}

void show_prompt (bool endl_before) {
	string_t prompt = "chatportal";

	if (CLIENT_USERNAME.empty()) {
		prompt += "::>> ";
	}
	else {
		prompt += ":" + CLIENT_USERNAME + ":>> ";
	}

	cout.flush();

	if (endl_before) cout << endl;
	cout << prompt;
	
	cout.flush();
}

void help () {
	cout << "Use the following commands to interact with the chat portal:" << endl;
	cout << "/register <uname> <pword>" << endl;
	cout << "/login <uname> <pword>" << endl;
	cout << "/logout" << endl;
	cout << "/msg <to_uname>" << endl;
	cout << "/exit" << endl;
}

// Local methods

void log_out_user (fd_t &fd, map_string_connection_t &connected_users)
{
	send_composed_message (fd, const_enums::CMD, const_enums::LOG_OUT);
	int rc = recv_ACK (fd);
	assert (rc != 0);

	if (rc == 1) {
		close_fd (fd);

		map_string_connection_t::iterator it = connected_users.begin();
		for (; it != connected_users.end(); it++) {
			if ((it -> second).conn_fd >= 0)
				close_fd ((it -> second).conn_fd);

			SSL_free ((it -> second).ssl);
			SSL_CTX_free ((it -> second).ctx);
		}

		connected_users.clear();

		CLIENT_USERNAME.clear();
		CLIENT_PASSWORD.clear();
		CLIENT_IP_ADDR.clear();
		CLIENT_CERTFILE.clear();
		CLIENT_KEYFILE.clear();
	}
}

void msg_user (fd_t &fd, map_string_connection_t &connected_users, const vector_string_t client_request)
{
	string_t to_uname = client_request[1];
	char input_message[2049];

	bzero (input_message, 2049);
	cout << "Enter Message: ";
	cin.getline (input_message, 2048);

	string_t message;
	message.assign (input_message);

	if (!map_contains_key (connected_users, to_uname)) {
		connect_to_user (fd, connected_users, to_uname);
		if (!map_contains_key (connected_users, to_uname)) {
			return;
		}
	}

	connection_data_t data = connected_users[to_uname];

	sleep(1);

	// SSL_write (data.ssl, (char*)message.c_str(), message.size());

	SSL_send_composed_message (data.ssl, const_enums::CMD, const_enums::MSG, CLIENT_USERNAME, to_uname, message);
	// int rc = SSL_recv_ACK (data.ssl);
	// assert (rc != 0);

	map_string_connection_t::iterator it = connected_users.find(to_uname);
	connected_users.erase(it);
}

void connect_to_user (fd_t &server_fd, map_string_connection_t &connected_users, string_t to_uname)
{
	send_composed_message (server_fd, const_enums::CMD, const_enums::CONNECT_REQUEST, CLIENT_USERNAME, to_uname);

	vector_string_t server_response;
	recv_composed_message (server_fd, server_response);

	if (is_negative_ACK (server_response)) {
		cout << "Server could not open the port" << endl;
		return;
	}

	// SOH,CMD,CONNECT_RES,FROM,TO,IP,PORT,EOT

	assert (server_response[3].compare(to_uname) == 0);

	int port, custsel;
	string_t ip_addr;
	cout << "Do you want to set custom IP addr and port (1) OR type (0) to continue: ";
	cin >> custsel;

	if (custsel == 0)
		ip_addr = server_response[5];
	else {
		cout << "IP Addr: ";
		cin >> ip_addr;
	}

	if (custsel == 0)
		port = string_to_integer (server_response[6]);
	else {
		cout << "PORT: ";
		cin >> port;
	}

	fd_t connect_fd;
	OpenConnection (connect_fd, ip_addr, port);
	
	if (custsel == 0)
		cout << "INFO " << "@connect_to_user: " << "Connected to user " << server_response[3] << endl;
	else
		cout << "INFO " << "@connect_to_user: " << "Connected" << endl;

	connection_data_t data;
	data.username = server_response[3];
	data.conn_fd = connect_fd;

	// TLS
	data.ctx = InitSSLCTX (2, CLIENT_CERTFILE, CLIENT_KEYFILE);
	data.ssl = SSL_new (data.ctx);
	SSL_set_fd (data.ssl, data.conn_fd);

	int rc;
	// TLS Handshake
	if ((rc = SSL_connect (data.ssl)) == -1)			/* perform the connection */
	{
		ERR_print_errors_fp (stderr);
		rc = SSL_get_error(data.ssl, rc);
		switch (rc) {
			case SSL_ERROR_NONE:
				cout << "SSL_ERROR_NONE" << endl;
				break;
			case SSL_ERROR_ZERO_RETURN:
				cout << "SSL_ERROR_ZERO_RETURN" << endl;
				break;
			case SSL_ERROR_WANT_READ:
				cout << "SSL_ERROR_WANT_READ" << endl;
				break;
			case SSL_ERROR_WANT_WRITE:
				cout << "SSL_ERROR_WANT_WRITE" << endl;
				break;
			case SSL_ERROR_WANT_CONNECT:
				cout << "SSL_ERROR_WANT_CONNECT" << endl;
				break;
			case SSL_ERROR_WANT_ACCEPT :
				cout << "SSL_ERROR_WANT_ACCEPT" << endl;
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				cout << "SSL_ERROR_WANT_X509_LOOKUP" << endl;
				break;
			case SSL_ERROR_SYSCALL:
				cout << "SSL_ERROR_SYSCALL" << endl;
				break;
			case SSL_ERROR_SSL:
				cout << "SSL_ERROR_SSL" << endl;
				break;
			default:
				cout << "UNKNOWN ERROR" << endl;
				break;
		}

		cout << "Connect failed." << endl;
	}
	else
	{
		int res = SSL_get_verify_result(data.ssl);
		if (X509_V_OK == res) {
			cout << "Certificate verified successfuly." << endl;
		}
		else {
			cout << "Certificate verification failed." << endl;
			return;
		}

		cout << "Connected with " << SSL_get_cipher (data.ssl) << " encryption" << endl;
		cout << endl;
		ShowServerCerts (data.ssl);					/* get any certs */
		cout << endl;
	}

	connected_users[data.username] = data;
}
