#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/client_head.h"

int MAX_OPEN_FD = -1;

/**
	All local prototypes described here.
 */

void run_client ();

/**
	All the functions defined here.
 */

int main () {
	signal (SIGINT, sigint_handler);
	signal (SIGSEGV, sigint_handler);
	signal (SIGABRT, sigint_handler);
	
	run_client ();
	return 0;
}

void run_client () {
	using namespace std;

	int user_choice;
	char user_input[1025];
	bool break_loop = false;

	help ();
	cin.get();		// Pause

	do
	{
		system ("clear");

		show_prompt ();
		cin.getline (user_input, 1024);

		vector_string_t user_input_split;
		if (string_t (user_input).empty() == false) {
			split_message (user_input, " ", user_input_split);
		}
		else
		{
			cout << "Invalid command! Please type \"/help\" at the prompt to view valid commands." << endl;
			cin.get();		// Pause
			continue;
		}

		switch (client_const::CLIENT_INPUT_COMMAND_MAP[user_input_split[0]])
		{
			case client_const::clnt_register:
			{
				if (user_input_split.size() != 3) {
					cout << "Invalid command! Please type \"/help\" at the prompt to view valid commands." << endl;
					cin.get();		// Pause
					break;
				}

				fd_t signup_sockfd;

				connect_to_signup_server (signup_sockfd);
				process_signup_request (signup_sockfd, user_input_split);
				cin.get();		// Pause
				break;
			}
			case client_const::clnt_login:
			{
				if (user_input_split.size() != 3) {
					cout << "Invalid command! Please type \"/help\" at the prompt to view valid commands." << endl;
					cin.get();		// Pause
					break;
				}

				fd_t signin_sockfd;

				connect_to_signin_server (signin_sockfd);
				process_signin_request (signin_sockfd, user_input_split);
				cin.get();		// Pause
				break;
			}
			case client_const::clnt_logout:
			case client_const::clnt_msg:
				cout << "You are not logged in! Please login before executing this command." << endl;
				cin.get();		// Pause
				break;
			case client_const::clnt_help:
				help();
				cin.get();		// Pause
				break_loop = false;
				break;
			case client_const::clnt_exit:
				break_loop = true;
				break;
			default:
				cout << "Invalid command! Please type \"/help\" at the prompt to view valid commands." << endl;
				cin.get();		// Pause
				break;
		}
	} while (break_loop == false);
}