#pragma once

#include <stddef.h>

namespace http_c
{
	class http_session_data
	{
	public:
		http_session_data(http::api::router<>& router) : session_handler_(router) {};

		http::session_handler session_handler_;

		std::vector<char> data_received_;
		std::vector<char> data_returned_;
	};


	class http_api_server
	{
	public:
		http_api_server() : router("") {};

		http_session_data* open_session() 
		{
			session_datas.push_back(new http_session_data(router));

			return session_datas.back();
		};

		void close_session(http_session_data* session)
		{
			session_datas.erase(std::find(std::begin(session_datas), std::end(session_datas), session));
		};

		int parse_session_data(http_session_data* session)
		{
			http::request_parser::result_type result;

			std::tie(result, std::ignore) = session->session_handler_.parse_request(std::begin(session->data_received_), std::end(session->data_received_));

			return static_cast<int>(result);
		}

		void handle_session(http_session_data* session)
		{
			session->session_handler_.handle_request();
		}

	protected:
		std::deque<http_session_data*> session_datas;
		http::api::router<> router;
	};
}


#ifdef __cplusplus
extern "C" {
#endif

typedef void* http_server_ptr;
typedef void* http_session_ptr;

extern "C" http_server_ptr http_server_create()
{
	return static_cast<http_server_ptr>(new http_c::http_api_server());
}

extern "C" void http_server_destroy(http_server_ptr server)
{
	delete static_cast<http_c::http_api_server*>(server);
}

extern "C" http_session_ptr http_open_session(http_server_ptr server)
{
	auto http_api_server = static_cast<http_c::http_api_server*>(server);

	return static_cast<http_session_ptr>(http_api_server->open_session());
}

extern "C" void http_close_session(http_server_ptr server, http_session_ptr session)
{
	auto http_api_server = static_cast<http_c::http_api_server*>(server);
	auto http_session = static_cast<http_c::http_session_data*>(session);

	http_api_server->close_session(http_session);
}

extern "C" int http_feed_session_data(http_session_ptr session, const char* data, size_t size)
{
	auto http_session = static_cast<http_c::http_session_data*>(session);

	http_session->data_received_.insert(std::end(http_session->data_received_), &data[0], &data[0] + size);

	return 0;
}

extern "C" int http_parse_session(http_server_ptr server, http_session_ptr session)
{
	auto http_api_server = static_cast<http_c::http_api_server*>(server);
	auto http_session = static_cast<http_c::http_session_data*>(session);

	return http_api_server->parse_session_data(http_session);
}

extern "C" void http_handle_session(http_server_ptr server, http_session_ptr session)
{
	auto http_api_server = static_cast<http_c::http_api_server*>(server);
	auto http_session = static_cast<http_c::http_session_data*>(session);

	http_api_server->handle_session(http_session);
}

extern "C" size_t http_retreive_session_response(http_session_ptr session_ptr, char** buffer)
{
	return 0;
}


#ifdef __cplusplus
}
#endif

