#include <iostream>

namespace util
{

std::string get_time_stamp()
{
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

	std::stringstream ss;
	std::tm buf;

	(void)gmtime_r(&in_time_t, &buf);

	ss << std::put_time(&buf, "%FT%T");
	ss << "." << msec << "Z";

	return ss.str();
}

std::size_t get_thread_id() noexcept
{
	static std::atomic<std::size_t> thread_idx{ 0 };
	thread_local std::size_t id = thread_idx;
	thread_idx++;
	return id;
}

template <typename... A> void log(const char* format) { printf("%s", format); }

template <typename... A> void log(const char* format, const A&... args)
{
	class argument
	{
	public:
		enum type
		{
			int_,
			string_,
			double_
		};
		type value_;
		union {
			int int_value;
			double dbl_value;
			const char* string_value;
		} u;

	public:
		argument(int value) : value_(int_) { u.int_value = value; }
		argument(double value) : value_(double_) { u.dbl_value = value; }
		argument(const char* value) : value_(string_) { u.string_value = value; }
	};

	enum class format_state
	{
		start,
		type,
		literal,
		end
	};

	argument argument_array[] = { args... };
	argument* a = argument_array;

	format_state state = format_state::literal;
	std::array<char, 255> buffer;
	size_t i = 0;

	for (; *format; format++)
	{
		switch (*format)
		{
			default:
				state = format_state::literal;
				buffer[i++] = *format;
				break;
			case '{':
				if (state == format_state::type)
				{
					state = format_state::literal;
					buffer[i++] = *format;
				}
				else
					state = format_state::type;
				break;
			case '}':
				if (state == format_state::literal)
				{
					state = format_state::type;
					buffer[i++] = *format;
				}
				else
					state = format_state::literal;
				break;
			case 's':
				if (state == format_state::type && a->value_ == argument::type::string_)
				{
					i += sprintf(&buffer[i], "%s", a++->u.string_value);
					state = format_state::end;
				}
				else
				{
					buffer[i++] = *format;
				}
				break;
			case 'd':
				if (state == format_state::type && a->value_ == argument::type::int_)
				{
					i += sprintf(&buffer[i], "%d", a++->u.int_value);
					state = format_state::literal;
				}
				else
				{
					buffer[i++] = *format;
				}
				break;
			case 'f':
				if (state == format_state::type && a->value_ == argument::type::double_)
				{
					i += sprintf(&buffer[i], "%f", a++->u.dbl_value);
					state = format_state::literal;
				}
				else
				{
					buffer[i++] = *format;
				}
				break;
		}
	}
	buffer[i++] = 0;

	printf("%s", &buffer[0]);
}

class prefixbuf : public std::streambuf
{
	std::string prefix_;

	std::streambuf* sbuf;
	bool need_prefix;

	int sync() { return this->sbuf->pubsync(); }
	int overflow(int c)
	{
		if (c != std::char_traits<char>::eof())
		{
			if (this->need_prefix && !this->prefix_.empty())
			{
				std::array<char, 64> prefix_buf;
				auto now = std::chrono::system_clock::now();
				auto in_time_t = std::chrono::system_clock::to_time_t(now);
				auto msec
					= std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

				std::tm buf;
				(void)gmtime_r(&in_time_t, &buf);

				auto prefix_size = snprintf(
					&prefix_buf[0],
					prefix_buf.size(),
					"%04d-%02d-%02dT%02d:%02d:%02d.%lldZ T%llu %s: ",
					buf.tm_year + 1900,
					buf.tm_mon + 1,
					buf.tm_mday,
					buf.tm_hour,
					buf.tm_min,
					buf.tm_sec,
					msec,
					get_thread_id(),
					prefix_.data());

				if (static_cast<std::streamsize>(prefix_buf.size()) != this->sbuf->sputn(&prefix_buf[0], prefix_size))
				{
					return std::char_traits<char>::eof();
				}
			}
			this->need_prefix = c == '\n';
		}
		return this->sbuf->sputc(static_cast<char>(c));
	}

public:
	prefixbuf(std::string const& prefix, std::streambuf* sbuf) : prefix_(prefix), sbuf(sbuf), need_prefix(true) {}
};

class oprefixstream : private virtual prefixbuf, public std::ostream
{
public:
	oprefixstream(std::string const& prefix, std::ostream& out_stream)
		: prefixbuf(prefix, out_stream.rdbuf())
		, std::ios(static_cast<std::streambuf*>(this))
		, std::ostream(static_cast<std::streambuf*>(this))
	{
	}
};

} // namespace util
