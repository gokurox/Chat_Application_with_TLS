#include "./sysheads.h"
#include "./common_head.h"

#ifndef CLIENT_H
#define CLIENT_H

// Constants
const int MAX_FILE_SIZE_MB = 5;
const int MAX_FILE_SIZE_KB = MAX_FILE_SIZE_MB * 1024;
const int MAX_FILE_SIZE_B = MAX_FILE_SIZE_KB * 1024;

static string_t CLIENT_USERNAME;
static string_t CLIENT_PASSWORD;
static string_t CLIENT_IP_ADDR;
static string_t CLIENT_CERTFILE;
static string_t CLIENT_KEYFILE;

struct connection_data_t
{
	string_t username;
	fd_t conn_fd;

	// May be required
	// fd_t listen_fd;
	// int listen_port;

	// OpenSSL requirements
	SSL *ssl;
	SSL_CTX *ctx;
};

typedef std::map<string_t, connection_data_t> map_string_connection_t;

const string_t CLIENT_INPUT_COMMAND[] = {
	"/register",
	"/login",
	"/logout",
	"/msg",
	"/help",
	"/exit"
};

namespace client_const
{
	enum ClientInputCommand {
		ClientInputCommand_start,
		clnt_register,
		clnt_login,
		clnt_logout,
		clnt_msg,
		clnt_help,
		clnt_exit,
		ClientInputCommand_end
	};

	static std::map<string_t, ClientInputCommand> CLIENT_INPUT_COMMAND_MAP = {
		{CLIENT_INPUT_COMMAND[0], clnt_register},
		{CLIENT_INPUT_COMMAND[1], clnt_login},
		{CLIENT_INPUT_COMMAND[2], clnt_logout},
		{CLIENT_INPUT_COMMAND[3], clnt_msg},
		{CLIENT_INPUT_COMMAND[4], clnt_help},
		{CLIENT_INPUT_COMMAND[5], clnt_exit}
	};
}

// Prototypes
void connect_to_signup_server (fd_t &);
void connect_to_signin_server (fd_t &);

void process_signup_request (fd_t &, const vector_string_t);
void process_signin_request (fd_t &, const vector_string_t);

void show_prompt (bool endl_before=false);
void help();

#endif