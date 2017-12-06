#pragma once

#include <stddef.h>

typedef void* http_session_ptr;

namespace http_c
{
	class http_session_data;

	class http_api_server
	{
	public:
		http_api_server() : router(""), session_handler_(router) {};

		http_session_data* create_session();
		void destroy_session();

		void store_session_data(const char* data);
		void retreive_session_data(const char* data);

		int handle_session();

	protected:
		std::deque<http_session_data*> session_datas;
		http::api::router<> router;

		http::session_handler session_handler_;
	};

	class http_session_data
	{
	public:
		http_session_data() {};

		std::vector<char> data_received_;
		std::vector<char> data_returned_;

	};
}


#ifdef __cplusplus
extern "C" {
#endif

typedef void* http_server_ptr;

extern "C" http_server_ptr http_server_create()
{
	return static_cast<http_server_ptr>(new http_c::http_api_server());
}

extern "C" void http_server_destroy(http_server_ptr server)
{
	delete static_cast<http_c::http_api_server*>(server);
}

extern "C" http_session_ptr http_session_create(http_server_ptr server)
{
}

extern "C" void http_sesion_destroy(http_server_ptr server, http_session_ptr session)
{
}

/*
extern "C" http_session_ptr construct_slm_rest_http_session()
{
	slm_rest_server::http_session_data_registry.push_back(new http_session_data(slm_rest_server::router));

	auto i = slm_rest_server::http_session_data_registry.back();

	return reinterpret_cast<http_session_ptr>(i);
}

extern "C" void destruct_slm_rest_http_session(http_session_ptr session_ptr)
{
}

extern "C" int slm_rest_http_session_handle_request(http_session_ptr session_ptr, const char* buffer, size_t size)
{
	http_session_data* session = reinterpret_cast<http_session_data*>(session_ptr);

	session->data_received_.insert(std::end(session->data_received_), &buffer[0], &buffer[size]);


	http::request_parser::result_type result;

	std::tie(result, std::ignore) = session->session_handler_.parse_request(std::begin(session->data_received_), std::end(session->data_received_));

	if (result == http::request_parser::result_type::good)
	{
		session->session_handler_.handle_request();
		session->data_returned_.clear();
		session->data_returned_ += session->session_handler_.reply().headers_to_string();
		session->data_returned_ += session->session_handler_.reply().content_to_string();
	}

	return 0;
}

extern "C" size_t slm_rest_http_session_get_reply(http_session_ptr session_ptr, char** buffer)
{
	http_session_data* session = reinterpret_cast<http_session_data*>(session_ptr);
	size_t size = session->data_returned_.length();
	*buffer = (char*)session->data_returned_.c_str();
	return size;
}

*/

#ifdef __cplusplus
}
#endif

