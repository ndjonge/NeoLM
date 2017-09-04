#include "http.h"
#include "server.h"


int main(int argc, char* argv[])
{

	http::server<http::connection_handler_http, http::connection_handler_https> server(
		"C:\\Development Libraries\\ssl.crt", 
		"C:\\Development Libraries\\ssl.key");

	server.start_server();

	return 0;
}

