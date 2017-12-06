#pragma once

#include <stddef.h>

typedef void* http_session_ptr;

namespace http_c
{
	class http_session_data;

	class http_api_server
	{
	public:
		http_api_server() = default;

	protected:
		static std::deque<http_session_data*> session_data_registry;
		static http::api::router<> router;
	};

	class http_session_data
	{
	public:
		http_session_data(http::api::router<>& router) : session_handler_(router) {};

		std::vector<char> data_received_;
		std::string data_returned_;

		http::session_handler session_handler_;
	};
}


#ifdef __cplusplus
extern "C" {
#endif

	http_session_ptr  construct_slm_rest_http_session(void);
	void  destruct_slm_rest_http_session(http_session_ptr session);

	int slm_rest_http_session_handle_request(http_session_ptr session_ptr, const char* buffer, size_t size);
	size_t slm_rest_http_session_get_reply(http_session_ptr session_ptr, char** buffer);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus__

#include "http.h"

class http_session
{
public:
	http_session() = default;
	~http_session() = default;

	http_session(const int connection_number) : connection_number_(connection_number) {};
	http_session(http_session& rhs) : connection_number_(rhs.connection_number_), request_(rhs.request_), reply_(rhs.reply_) {};

	int& connection_number() noexcept { return connection_number_; }
private:
	int connection_number_;
	http::request request_;
	http::reply reply_;
};

static auto http_sessions = std::make_unique<std::vector<http_session>>();

extern  "C" http_session* http_session_create(int connection_nr)
{
	static auto http_sessions = std::make_unique<std::vector<http_session>>();

	http_sessions->emplace_back(connection_nr);

	return &(http_sessions->back());
}

extern "C" void http_session_destroy(int connection_nr)
{
	std::remove_if(std::begin(*http_sessions), std::end(*http_sessions), [connection_nr](http_session& session_handle)
	{
		return session_handle.connection_number() == connection_nr;
	});
}

#endif

