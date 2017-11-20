#pragma once

#define __STDC_WANT_LIB_EXT1__ 1
#include <sstream>
#include <string>
#include <time.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>

#include <deque>
#include <thread>
#include <vector>

#include <ctime>

#include <map>
#include <type_traits>
#include <algorithm>

#include "http.h"

namespace http
{

namespace misc_strings
{

	const char name_value_separator[] = { ':', ' ' };
	const char crlf[] = { '\r', '\n' };

} // namespace misc_strings

namespace stock_replies
{

	const char ok[] = "";
	const char created[]
		= "<html>"
		"<head><title>Created</title></head>"
		"<body><h1>201 Created</h1></body>"
		"</html>";
	const char accepted[]
		= "<html>"
		"<head><title>Accepted</title></head>"
		"<body><h1>202 Accepted</h1></body>"
		"</html>";
	const char no_content[]
		= "<html>"
		"<head><title>No Content</title></head>"
		"<body><h1>204 Content</h1></body>"
		"</html>";
	const char multiple_choices[]
		= "<html>"
		"<head><title>Multiple Choices</title></head>"
		"<body><h1>300 Multiple Choices</h1></body>"
		"</html>";
	const char moved_permanently[]
		= "<html>"
		"<head><title>Moved Permanently</title></head>"
		"<body><h1>301 Moved Permanently</h1></body>"
		"</html>";
	const char moved_temporarily[]
		= "<html>"
		"<head><title>Moved Temporarily</title></head>"
		"<body><h1>302 Moved Temporarily</h1></body>"
		"</html>";
	const char not_modified[]
		= "<html>"
		"<head><title>Not Modified</title></head>"
		"<body><h1>304 Not Modified</h1></body>"
		"</html>";
	const char bad_request[]
		= "<html>"
		"<head><title>Bad Request</title></head>"
		"<body><h1>400 Bad Request</h1></body>"
		"</html>";
	const char unauthorized[]
		= "<html>"
		"<head><title>Unauthorized</title></head>"
		"<body><h1>401 Unauthorized</h1></body>"
		"</html>";
	const char forbidden[]
		= "<html>"
		"<head><title>Forbidden</title></head>"
		"<body><h1>403 Forbidden</h1></body>"
		"</html>";
	const char not_found[]
		= "<html>"
		"<head><title>Not Found</title></head>"
		"<body><h1>404 Not Found</h1></body>"
		"</html>";
	const char internal_server_error[]
		= "<html>"
		"<head><title>Internal Server Error</title></head>"
		"<body><h1>500 Internal Server Error</h1></body>"
		"</html>";
	const char not_implemented[]
		= "<html>"
		"<head><title>Not Implemented</title></head>"
		"<body><h1>501 Not Implemented</h1></body>"
		"</html>";
	const char bad_gateway[]
		= "<html>"
		"<head><title>Bad Gateway</title></head>"
		"<body><h1>502 Bad Gateway</h1></body>"
		"</html>";
	const char service_unavailable[]
		= "<html>"
		"<head><title>Service Unavailable</title></head>"
		"<body><h1>503 Service Unavailable</h1></body>"
		"</html>";

} // namespace stock_replies

class field
{
public:
	field() = default;

	field(const std::string& name, const std::string& value = "")
		: name(name)
		, value(value)
	{
	};

	std::string name;
	std::string value;
};


template<bool is_reqeust> class header;

template<> class header<true>
{
public:
	std::string method_;
	std::string uri_;
	std::string body_;

	unsigned int version_;
	std::vector<http::field> fields_;

	std::string& method()
	{
		return method_;
	}

	std::string& uri()
	{
		return uri_;
	}

	unsigned int& version()
	{
		return version_;
	}

	std::vector<http::field>& fields()
	{
		return fields_;
	}

	void reset()
	{
		this->fields_.clear();
		this->body_.clear();
	}

	void set(const std::string& name, const std::string& value)
	{
		http::field field_(name, value);
		fields_.emplace_back(std::move(field_));
	}

	const std::string& operator[](const std::string& name) const
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f)
		{
			if (f.name == name)
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
			return "";
		else
			return i->value;
	}

};

template<> class header<false>
{
public:
	enum status_type
	{
		ok = 200,
		created = 201,
		accepted = 202,
		no_content = 204,
		multiple_choices = 300,
		moved_permanently = 301,
		moved_temporarily = 302,
		not_modified = 304,
		bad_request = 400,
		unauthorized = 401,
		forbidden = 403,
		not_found = 404,
		internal_server_error = 500,
		not_implemented = 501,
		bad_gateway = 502,
		service_unavailable = 503
	} status_t;

	std::string reason_;
	status_type status_;
	unsigned int version_ = 11;

	std::vector<http::field> fields_;

	std::vector<http::field>& fields() { return fields_; }

	unsigned int& version() noexcept
	{
		return version_;
	}

	void version(unsigned int value) noexcept
	{
		version_ = value;
	}

	void reset()
	{
		this->fields_.clear();
	}

	std::string header_to_string()
	{
		std::stringstream ss;

		for (auto&& field : fields_)
		{
			ss << "\"" << field.name << "\":";
			ss << "\"" << field.value << "\"";
		}

		return ss.str();
	}

	void set(const std::string& name, const std::string& value)
	{
		http::field field_(name, value);
		fields_.emplace_back(std::move(field_));
	}

	const std::string& operator[](const std::string& name) const
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f)
		{
			if (f.name == name)
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
			return "";
		else
			return i->value;
	}

};

using request_header = header<true>;
using reply_header = header<false>;

template<bool is_request> class message : public header<is_request>
{
public:
	std::string body_;


	static header<is_request> create_stock_reply(reply_header::status_type status, const std::string& extension = "text/plain")
	{
		header<is_request> reply_;

		reply.stock_reply(status, extension);

		return reply_;
	}

	/// Get a stock reply.
	void stock_reply(reply_header::status_type status, const std::string& extension = "text/plain")
	{
		status_ = status;

		if (status != ok)
		{
			body_ = std::to_string(status_);
		}
		
		set("Server", "NeoLM / 0.01 (Windows)");
		set("Content-Type", mime_types::extension_to_type(extension));
	}
};

using request = http::message<true>;
using reply = http::message<false>;

} // namespace http
