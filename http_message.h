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

namespace util
{
	inline bool case_insensitive_equal(const std::string& str1, const std::string& str2) noexcept
	{
		return str1.size() == str2.size() && std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) { return tolower(a) == tolower(b); });
	}
}

namespace status
{
	enum status_t
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
	};

	const char* to_string(status_t s)
	{
		switch (s)
		{
		case http::status::ok:						return "HTTP/1.1 200 OK\r\n";
		case http::status::created:					return "HTTP/1.1 202 Accepted\r\n";
		case http::status::accepted:				return "HTTP/1.1 204 No Content\r\n";
		case http::status::no_content:				return "HTTP/1.1 204 No Content\r\n";
		case http::status::multiple_choices:		return "HTTP/1.1 300 Multiple Choices\r\n";
		case http::status::moved_permanently:		return "HTTP/1.1 301 Moved Permanently\r\n";
		case http::status::moved_temporarily:		return "HTTP/1.1 302 Moved Temporarily\r\n";
		case http::status::not_modified:			return "HTTP/1.1 304 Not Modified\r\n";
		case http::status::bad_request:				return "HTTP/1.1 400 Bad Request\r\n";
		case http::status::unauthorized:			return "HTTP/1.1 401 Unauthorized\r\n";
		case http::status::forbidden:				return "HTTP/1.1 403 Forbidden\r\n";
		case http::status::not_found:				return "HTTP/1.1 404 Not Found\r\n";
		case http::status::internal_server_error:	return "HTTP/1.1 500 Internal Server Error\r\n";
		case http::status::not_implemented:			return "HTTP/1.1 501 Not Implemented\r\n";
		case http::status::bad_gateway:				return "HTTP/1.1 502 Bad Gateway\r\n";
		case http::status::service_unavailable:		return "HTTP/1.1 503 Service Unavailable\r\n";
		default:									return "";
		}
	}
} // namespace status_strings



namespace misc_strings
{
	const char name_value_separator[] = { ':', ' ' };
	const char crlf[] = { '\r', '\n' };
} // namespace misc_strings

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

class fields
{
protected:
	std::vector<http::field> fields_;

public:
	using iterator = std::vector<http::field>::iterator;

	bool fields_empty() const { return this->fields_.empty(); };

	void set(const std::string& name, const std::string& value)
	{
		http::field field_(name, value);

		fields_.emplace_back(std::move(field_));
	}

	auto new_field()
	{
		fields_.push_back(field());
		return fields_.rbegin();
	}

	auto last_new_field()
	{
		return fields_.rbegin();
	}

	const std::string get(const std::string& name) const
	{
		return this->operator[](name);
	}

	const std::string operator[](const std::string& name) const
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f)
		{
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
			return {};
		else
			return i->value;
	}
};

template<> class header<true> : public fields
{
public:
	std::string method_;
	std::string target_;
	std::string body_;

	unsigned int version_;

	std::string& method()
	{
		return method_;
	}

	std::string& target()
	{
		return target_;
	}

	unsigned int& version()
	{
		return version_;
	}

	void reset()
	{
		this->method_.clear();
		this->target_.clear();
		this->body_.clear();
		this->fields_.clear();
	}
};

template<> class header<false> : public fields
{
public:
	std::string reason_;
	http::status::status_t status_;
	unsigned int version_ = 11;

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
};

using request_header = header<true>;
using reply_header = header<false>;

template<bool is_request> class message : public header<is_request>
{
public:
	std::string body_;	

	bool chunked() const
	{				
		return (this->get("Transfer-Encoding") == "chunked");
	}

	void chunked(bool value)
	{
		if (value)
			fields::set("Transfer-Encoding", "chunked")
		else
			fields::set("Transfer-Encoding", "none")
	}

	bool has_content_lenght() const
	{
		if (fields::operator["Content-Length"] != "")
			return true;
		else
			return false;
	}

	void content_length(uint64_t const& length) const
	{
		fields::set("Content-Length", std::to_string(lenght))
	}

	bool keep_alive() const
	{
		if (fields::["Connection"] != "Keep-Alive")
			return true;
		else
			return false;
	}

	void keep_alive(bool value)
	{
		if (value)
			this->set("Connection", "Keep-Alive")
	}

	static header<is_request> create_stock_reply(http::status::status_t status, const std::string& extension = "text/plain")
	{
		header<is_request> reply_;

		reply.stock_reply(status, extension);

		return reply_;
	}

	/// Get a stock reply.
	void stock_reply(http::status::status_t status, const std::string& extension = "text/plain")
	{
		status_ = status;

		if (status != http::status::ok)
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
