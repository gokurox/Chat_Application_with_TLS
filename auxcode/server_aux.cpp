#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/server_head.h"

using namespace std;

/**
	All the local prototypes described here.
 */

void setup_server_for_signup (fd_t &);
void setup_server_for_signin (fd_t &);

// Functions implementing specific commands
void register_user (fd_t &, map_string_string_t &, const vector_string_t);
void log_in_user (fd_t &, map_string_string_t, map_string_fd_t &, const vector_string_t);
void log_out_user (fd_t &, vector_fd_t &, map_string_fd_t &);
void msg_user (fd_t &, map_string_fd_t, const vector_string_t);
void forward_connect_request (fd_t &, map_string_fd_t, vector_string_t);

/**
	All above described functions are defined here.
 */

// Server related functions

void server_setup (fd_t &signup_fd, fd_t &signin_fd) {
	setup_server_for_signup (signup_fd);
	setup_server_for_signin (signin_fd);
}

void setup_server_for_signup (fd_t &signup_fd)
{
	sockaddr_in signup_sock;
	int rc;

	// Create Registration Socket
	signup_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (signup_fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, signup_fd);	

	// Initialize Socket
	bzero ((char *)(&signup_sock), sizeof (signup_sock));

	signup_sock.sin_family = AF_INET;
	signup_sock.sin_port = htons (SIGNUP_PORT_NUM);
	inet_pton (AF_INET , SERVER_IPv4_ADDR.c_str(), &(signup_sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (signup_fd, (sockaddr *)(&signup_sock), sizeof (signup_sock));
	assert (rc >= 0);

	// Listen on the ports for incoming connections
	rc = listen (signup_fd, MAX_LISTEN_LIMIT);
	assert (rc >= 0);

	cout << "INFO " << "@setup_server_for_signup: " << "Server listening for signup connection @port:" << SIGNUP_PORT_NUM << endl;
}

void setup_server_for_signin (fd_t &signin_fd)
{
	sockaddr_in signin_sock;
	int rc;

	// Create Registration Socket
	signin_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (signin_fd >= 0);
	MAX_OPEN_FD = max (MAX_OPEN_FD, signin_fd);	

	// Initialize Socket
	bzero ((char *)(&signin_sock), sizeof (signin_sock));

	signin_sock.sin_family = AF_INET;
	signin_sock.sin_port = htons (SIGNIN_PORT_NUM);
	inet_pton (AF_INET , SERVER_IPv4_ADDR.c_str(), &(signin_sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (signin_fd, (sockaddr *)(&signin_sock), sizeof (signin_sock));
	assert (rc >= 0);

	// Listen on the ports for incoming connections
	rc = listen (signin_fd, MAX_LISTEN_LIMIT);
	assert (rc >= 0);

	cout << "INFO " << "@setup_server_for_signin: " << "Server listening for signin connection @port:" << SIGNIN_PORT_NUM << endl;
}

void add_to_conn_signup_fds (fd_t &signup_fd, vector_fd_t &conn_signup_fds) {
	assert (signup_fd >= 0);
	conn_signup_fds.push_back (signup_fd);
	
	cout << "INFO @add_to_conn_signup_fds: Added FD[" << signup_fd << "]." << endl;
	cout << "INFO @add_to_conn_signup_fds: Sending positive ack" << endl;
	send_positive_ACK (signup_fd, "Connection Accepted. Client OK to Sign Up.");
}

void add_to_conn_signin_fds (fd_t &signin_fd, vector_fd_t &conn_signin_fds) {
	assert (signin_fd >= 0);
	conn_signin_fds.push_back (signin_fd);
	
	cout << "INFO @add_to_conn_signin_fds: Added FD[" << signin_fd << "]." << endl;
	cout << "INFO @add_to_conn_signin_fds: Sending positive ack" << endl;
	send_positive_ACK (signin_fd, "Connection Accepted. Client OK to Sign In.");
}

void respond_to_signup_conn (fd_t &fd, vector_fd_t &conn_signup_fds, map_string_string_t &registered_users)
{
	vector_string_t request_vector;
	recv_composed_message (fd, request_vector);

	switch (const_maps::MSG_TYPE_MAP[request_vector[1]])
	{
		case const_enums::CMD:
		{	switch (const_maps::CMD_TYPE_MAP[request_vector[2]])
			{
				case const_enums::REG:
				{	
					register_user (fd, registered_users, request_vector);
					break;
				}
				default:
				{
					send_negative_ACK (fd, "Invalid Command for signup socket.");
					break;
				}
			}
			break;
		}
		case const_enums::CLOSE_CONN:
			close_fd (fd);
			break;
		default:
		{
			send_negative_ACK (fd, "Invalid Message Type for signup socket.");
			break;
		}
	}

	close_fd (fd, conn_signup_fds);
}

void respond_to_signin_conn (fd_t &fd, vector_fd_t &conn_signin_fds, map_string_string_t registered_users, map_string_fd_t &logged_in_users)
{
	vector_string_t client_request;
	recv_composed_message (fd, client_request);

	switch (const_maps::MSG_TYPE_MAP[client_request[1]])
	{
		case const_enums::CMD:
			switch (const_maps::CMD_TYPE_MAP[client_request[2]])
			{
				case const_enums::LOG_IN:
					log_in_user (fd, registered_users, logged_in_users, client_request);
					break;
				case const_enums::LOG_OUT:
					log_out_user (fd, conn_signin_fds, logged_in_users);
					break;
				case const_enums::CONNECT_REQUEST:
					forward_connect_request (fd, logged_in_users, client_request);
					break;
				default:
					cout << "WARNING " << "@respond_to_signin_conn:" << "Invalid Command." << endl;
					close_fd (fd, conn_signin_fds, logged_in_users);
					break;
			}
			break;
		case const_enums::ACK:
			break;
		case const_enums::CLOSE_CONN:
			close_fd (fd);
			break;
		default:
			break;
	}
}

// Functions implementing specific commands

void register_user (fd_t &fd, map_string_string_t &registered_users, const vector_string_t request_vector)
{
	string_t username = request_vector[3];
	string_t password = request_vector[4];

	if (map_contains_key (registered_users, username))
	{
		send_negative_ACK (fd, "Requested username already exists.");
		return;
	}
	else 
	{
		string_t filepath = DATABASE_DIR + USERPASS_FILE;
		string_t to_append = username + USERPASS_SEPERATOR + password;
		append_to_file (filepath, to_append, true);

		// Add to map
		registered_users [username] = password;

		send_positive_ACK (fd, "User registration successful.");
	}
}

void log_in_user (fd_t &fd, map_string_string_t registered_users, map_string_fd_t &logged_in_users, const vector_string_t client_request)
{
	string username = client_request[3];

	if (map_contains_key (registered_users, username) == false) {
		send_negative_ACK (fd, "User is not registered.");
		return;
	}

	if (map_contains_key (logged_in_users, username) || map_contains_value (logged_in_users, fd)) {
		send_negative_ACK (fd, "User is already logged in.");
		return;
	}

	string password = client_request[4];

	if (registered_users[username].compare (password) != 0) {
		send_negative_ACK (fd, "Credentials do not validate.");
		return;
	}

	logged_in_users [username] = fd;
	send_positive_ACK (fd, "User successfully logged in.");
}

void log_out_user (fd_t &fd, vector_fd_t &conn_signin_fds, map_string_fd_t &logged_in_users)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	send_positive_ACK (fd, "User successfully logged out.");

	close_fd (fd, conn_signin_fds, logged_in_users);
	assert (fd == -1);
}

void msg_user (fd_t &from_fd, map_string_fd_t logged_in_users, vector_string_t client_request)
{
	if (map_contains_value (logged_in_users, from_fd) == false) {
		send_negative_ACK (from_fd, "User is not logged in.");
		return;
	}

	string_t from_uname = client_request[3];
	string_t from_uname_ver = map_get_key_from_value (logged_in_users, from_fd);
	if (from_uname_ver.compare (from_uname) != 0) {
		send_negative_ACK (from_fd, "Given from_uname does not match the logged in user.");
		return;
	}

	string_t to_uname = client_request[4];

	if (map_contains_key (logged_in_users, to_uname) == false) {
		send_negative_ACK (from_fd, "Receiver is not Online.");
		return;
	}

	string_t user_message = client_request[5];

	fd_t to_fd = logged_in_users [to_uname];
	send_composed_message (to_fd, const_enums::CMD, const_enums::MSG, from_uname, to_uname, user_message);

	send_positive_ACK (from_fd, "Message delivered successfully.");
}

void forward_connect_request (fd_t &from_fd, map_string_fd_t logged_in_users, vector_string_t client_request)
{
	if (map_contains_value (logged_in_users, from_fd) == false) {
		send_negative_ACK (from_fd, "User is not logged in.");
		return;
	}

	string_t from_uname = client_request[3];
	string_t from_uname_ver = map_get_key_from_value (logged_in_users, from_fd);
	if (from_uname_ver.compare (from_uname) != 0) {
		send_negative_ACK (from_fd, "Given from_uname does not match the logged in user.");
		return;
	}

	string_t to_uname = client_request[4];

	if (map_contains_key (logged_in_users, to_uname) == false) {
		send_negative_ACK (from_fd, "Receiver is not Online.");
		return;
	}

	string_t user_message = client_request[5];

	fd_t to_fd = logged_in_users [to_uname];
	send_composed_message (to_fd, const_enums::CMD, const_enums::CONNECT_REQUEST, from_uname, to_uname);

	vector_string_t user_response;
	recv_composed_message (to_fd, user_response);

	send_composed_message (from_fd, const_enums::CMD, const_enums::CONNECT_RESPONSE, user_response[3], user_response[4], user_response[5], user_response[6]);
}

// Auxilliary functions

void read_registered_users (map_string_string_t &registered_users)
{
	string filepath = DATABASE_DIR + USERPASS_FILE;

	if (!file_exists (filepath)) {
		create_file (filepath);
		return;
	}

	string file;
	read_file (filepath, file);
	istringstream sstream (file);

	string uname, pword;
	while (sstream >> uname >> pword) {
		registered_users[uname] = pword;
		uname.clear ();
		pword.clear ();
	}
}