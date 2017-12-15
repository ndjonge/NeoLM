#pragma once

#define __STDC_WANT_LIB_EXT1__ 1

#include <sstream>
#include <string>
#include <algorithm>
#include <functional>
#include <deque>
#include <thread>
#include <vector>

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


class fields
{

public:
	using iterator = std::vector<http::field>::iterator;
	using value_type = http::field;

protected:
	std::vector<fields::value_type> fields_;

public:
	fields() = default;

	fields(std::initializer_list<fields::value_type> init_list) : fields_(init_list) {};

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

	const std::string& operator[](std::string name) const
	{
		static const std::string not_found = "";

		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f)
		{
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
		{			
			return not_found;
		}
		else
			return i->value;
	}

	std::string& operator[](const std::string& name)
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f)
		{
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
		{
			fields_.emplace_back(http::field(name, ""));
			return fields_.back().value;
		}
		else
			return i->value;
	}

};

using configuration = class http::fields;

enum message_specializations {
	request_specialization,
	response_specialization
};

template<message_specializations> class header;


template<> class header<request_specialization> : public fields
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

template<> class header<response_specialization> : public fields
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

	std::string header_to_string() const
	{
		std::stringstream ss;

		ss << status::to_string(status_);

		for (auto&& field : fields_)
		{
			ss << field.name << ":";
			ss << field.value << "\r\n";
		}

		ss << "\r\n";

		return ss.str();
	}
};

using request_header = header<request_specialization>;
using response_header = header<response_specialization>;

template<message_specializations specialization> class message : public header<specialization>
{
private:
	std::string body_;
public:
	std::string& body()
	{
		return body_;
	}

	const std::string& body() const
	{
		return body_;
	}

	bool chunked() const
	{				
		return (http::fields::operator[]("Transfer-Encoding") == "chunked");
	}

	void chunked(bool value)
	{
		if (value)
			http::fields::operator[]("Transfer-Encoding") = "chunked";
		else
			http::fields::operator[]("Transfer-Encoding") = "none";
	}

	bool has_content_lenght() const
	{
		if (http::fields::operator[]("Content-Length").empty())
			return false;
		else
			return true;
	}

	void content_length(uint64_t const& length)
	{
		http::fields::operator[]("Content-Length") = std::to_string(length);
	}

	const uint64_t content_length() const
	{
		return std::stoul(http::fields::operator[]("Content-Length"));
	}

	bool keep_alive() const
	{
		if (http::fields::operator[]("Connection") == "keep-alive")
			return true;
		else
			return false;
	}

	void keep_alive(bool value, int timeout = 0, int count = 0 )
	{
		if (value)
		{
			fields::set("Connection", "keep-alive");
			fields::set("Keep_Alive", "timeout=" + std::to_string(timeout) + ", max" + std::to_string(count));
		}
	}

	static header<specialization> create_stock_reply(http::status::status_t status, const std::string& extension = "text/plain")
	{
		// move to header<request> specialization?

		header<specialization> reply_;

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

	static std::string to_string(const http::message<specialization>& message)
	{
		std::string ret = message.header_to_string();
		ret += message.body();

		return ret;
	}
};

template <message_specializations specialization>
std::string to_string(const http::message<specialization>& message)
{
	return http::message<specialization>::to_string(message);
}

using request_message = http::message<request_specialization>;
using response_message = http::message<response_specialization>;

} // namespace http
