#pragma once

#include <stddef.h>

#include "http.h"
#include "http_api.h"


namespace http
{

namespace basic
{

class session_data
{
public:
	session_data() {};

	void store_data(const char* data, size_t size)
	{
		data_received_.insert(std::end(data_received_), &data[0], &data[0] + size);
	}

	std::vector<char>& data_received() { return data_received_; }

private:
	std::vector<char> data_received_;
};

class server
{
public:
	server(std::initializer_list<http::configuration::value_type> init_list) : session_handler_(router), router(""), configuration_(init_list) {};

	session_data* open_session() 
	{
		session_datas.push_back(new session_data);

		return session_datas.back();
	};

	void close_session(session_data* session)
	{
		session_datas.erase(std::find(std::begin(session_datas), std::end(session_datas), session));
	};

	http::request_parser::result_type parse_session_data(session_data* session)
	{
		http::request_parser::result_type result;

		std::tie(result, std::ignore) = session_handler_.parse_request(std::begin(session->data_received()), std::end(session->data_received()));

		return result;
	}

	http::response_message& handle_session(session_data* session)
	{
		session_handler_.handle_request();

		return session_handler_.response();
	}

protected:
	std::deque<session_data*> session_datas_;
	http::session_handler session_handler_;
	http::api::router<> router_;
	http::configuration configuration_;
};

} // basic

} // http


