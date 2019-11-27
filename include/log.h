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

namespace logger
{

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
				std::string tmp;
				tmp = get_time_stamp();
				this->sbuf->sputn(&tmp[0], tmp.size());
				this->sbuf->sputn(" ", 1);

				tmp = "T" + std::to_string(get_thread_id());

				this->sbuf->sputn(&tmp[0], tmp.size());
				this->sbuf->sputn(" ", 1);

				if (static_cast<std::streamsize>(this->prefix_.size())
					!= this->sbuf->sputn(&this->prefix_[0], this->prefix_.size()))
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

} // namespace logger

} // namespace util
