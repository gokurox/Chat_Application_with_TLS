#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/server_head.h"

int MAX_OPEN_FD = -1;

void run_server ();

int main() 
{
	signal (SIGINT, sigint_handler);
	signal (SIGSEGV, sigint_handler);
	signal (SIGABRT, sigint_handler);

	run_server ();
	return 0;
}

void run_server ()
{
	using namespace std;

	// Variables required for Initializing server
	fd_t
		signup_sockfd,					// Registration Port Server File Descriptor
		signin_sockfd;					// Login Port File Server Descriptor

	// Initialize server and setup to listen to the concerned ports
	server_setup (signup_sockfd, signin_sockfd);
	assert ((signup_sockfd >= 0) && (signin_sockfd >= 0));

	// Variables required for Server Functioning
	fd_t max_fd;
	fd_set sockfd_set;				// Set for open file descriptors
	
	vector_fd_t
		conn_signup_fds,			// All connected register socket fds
		conn_signin_fds;			// All connected login socket fds

	map_string_string_t registered_users;			// Registered users --> passwords

	read_registered_users (registered_users);

	map_string_fd_t logged_in_users;				// All logged in users (validated) with their fds

	vector_filestorage_t pending_file_operations;

	while (true) {
		// Clear the Socket Set
		FD_ZERO (&sockfd_set);

		// Add Registration and Login Sockets to set
		FD_SET (signup_sockfd, &sockfd_set);
		FD_SET (signin_sockfd, &sockfd_set);

		max_fd = max (signup_sockfd, signin_sockfd);

		// Add all registration sockets to sockfd_set
		for (fd_t fd: conn_signup_fds) {
			if (fd > 0) {
				FD_SET (fd, &sockfd_set);
				max_fd = max (fd, max_fd);
			}
			// else {
			// 	close_fd (fd, conn_signup_fds);
			// }
		}

		// Add all login sockets to sockfd_set
		for (fd_t fd: conn_signin_fds) {
			if (fd > 0) {
				FD_SET (fd, &sockfd_set);
				max_fd = max (fd, max_fd);
			}
			// else {
			// 	close_fd (fd, conn_signin_fds);
			// }
		}

		select (max_fd +1, &sockfd_set, NULL, NULL, NULL);

		if (FD_ISSET (signup_sockfd, &sockfd_set)) {
			fd_t fd = accept (signup_sockfd, NULL, NULL);
			MAX_OPEN_FD = max (MAX_OPEN_FD, fd);	
			cout << "INFO " << "@run_server: " << "Accepted a signup connection" << endl;
			add_to_conn_signup_fds (fd, conn_signup_fds);
		}

		if (FD_ISSET (signin_sockfd, &sockfd_set)) {
			fd_t fd = accept (signin_sockfd, NULL, NULL);
			MAX_OPEN_FD = max (MAX_OPEN_FD, fd);	
			cout << "INFO " << "@run_server: " << "Accepted a signin connection" << endl;
			add_to_conn_signin_fds (fd, conn_signin_fds);
		}

		for (int i = 0; i < conn_signup_fds.size(); i++) {
			if (i >= conn_signup_fds.size())
				break;
			
			if (conn_signup_fds[i] < 0)
				continue;

			if (FD_ISSET (conn_signup_fds[i], &sockfd_set)) {
				respond_to_signup_conn (conn_signup_fds[i], conn_signup_fds, registered_users);
			}
		}

		for (int j = 0; j < conn_signin_fds.size(); j++) {
			if (j >= conn_signin_fds.size())
				break;
			
			if (conn_signin_fds[j] < 0)
				continue;

			if (FD_ISSET (conn_signin_fds[j], &sockfd_set)) {
				respond_to_signin_conn (conn_signin_fds[j], conn_signin_fds, registered_users, logged_in_users);
			}
		}
	}
}