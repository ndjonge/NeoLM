#include "http.h"
#include "server.h"


int main(int argc, char* argv[])
{

	http::server<http::client_connection_handler, http::ssl_client_connection_handler> server(
		"C:\\Development Libraries\\ssl.crt", 
		"C:\\Development Libraries\\ssl.key");

	server.start_server();

	return 0;
}

