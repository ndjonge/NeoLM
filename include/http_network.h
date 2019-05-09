/*
Copyright (c) <2018> <ndejonge@gmail.com>

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#ifdef IPV6STRICT
#undef IPV6STRICT
#endif

#include <csignal>
#include <cstdint>

#if defined(_WIN32)
#include <Ws2tcpip.h>
#include <winsock2.h>
#else
#define SOCKET int
#define closesocket close
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"

namespace network
{
using socket_t = SOCKET;
using error_code = std::int32_t;

namespace error
{
enum errc_t
{
	success = 0,
	address_family_not_supported = EAFNOSUPPORT,
	address_in_use = EADDRINUSE,
	address_not_available = EADDRNOTAVAIL,
	already_connected = EISCONN,
	argument_list_too_long = E2BIG,
	argument_out_of_domain = EDOM,
	bad_address = EFAULT,
	bad_file_descriptor = EBADF,
	bad_message = EBADMSG,
	broken_pipe = EPIPE,
	connection_aborted = ECONNABORTED,
	connection_already_in_progress = EALREADY,
	connection_refused = ECONNREFUSED,
	connection_reset = ECONNRESET,
	cross_device_link = EXDEV,
	destination_address_required = EDESTADDRREQ,
	device_or_resource_busy = EBUSY,
	directory_not_empty = ENOTEMPTY,
	executable_format_error = ENOEXEC,
	file_exists = EEXIST,
	file_too_large = EFBIG,
	filename_too_long = ENAMETOOLONG,
	function_not_supported = ENOSYS,
	host_unreachable = EHOSTUNREACH,
	identifier_removed = EIDRM,
	illegal_byte_sequence = EILSEQ,
	inappropriate_io_control_operation = ENOTTY,
	interrupted = EINTR,
	invalid_argument = EINVAL,
	invalid_seek = ESPIPE,
	io_error = EIO,
	is_a_directory = EISDIR,
	message_size = EMSGSIZE,
	network_down = ENETDOWN,
	network_reset = ENETRESET,
	network_unreachable = ENETUNREACH,
	no_buffer_space = ENOBUFS,
	no_child_process = ECHILD,
	no_link = ENOLINK,
	no_lock_available = ENOLCK,
	no_message_available = ENODATA,
	no_message = ENOMSG,
	no_protocol_option = ENOPROTOOPT,
	no_space_on_device = ENOSPC,
	no_stream_resources = ENOSR,
	no_such_device_or_address = ENXIO,
	no_such_device = ENODEV,
	no_such_file_or_directory = ENOENT,
	no_such_process = ESRCH,
	not_a_directory = ENOTDIR,
	not_a_socket = ENOTSOCK,
	not_a_stream = ENOSTR,
	not_connected = ENOTCONN,
	not_enough_memory = ENOMEM,
	not_supported = ENOTSUP,
	operation_canceled = ECANCELED,
	operation_in_progress = EINPROGRESS,
	operation_not_permitted = EPERM,
	operation_not_supported = EOPNOTSUPP,
	operation_would_block = EWOULDBLOCK,
	owner_dead = EOWNERDEAD,
	permission_denied = EACCES,
	protocol_error = EPROTO,
	protocol_not_supported = EPROTONOSUPPORT,
	read_only_file_system = EROFS,
	resource_deadlock_would_occur = EDEADLK,
	resource_unavailable_try_again = EAGAIN,
	result_out_of_range = ERANGE,
	state_not_recoverable = ENOTRECOVERABLE,
	stream_timeout = ETIME,
	text_file_busy = ETXTBSY,
	timed_out = ETIMEDOUT,
	too_many_files_open_in_system = ENFILE,
	too_many_files_open = EMFILE,
	too_many_links = EMLINK,
	too_many_symbolic_link_levels = ELOOP,
	value_too_large = EOVERFLOW,
	wrong_protocol_type = EPROTOTYPE
};

} // namespace error

inline void init()
{
#if defined(_WIN32)
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) exit(1);
#else
	signal(SIGPIPE, SIG_IGN); // NOLINT
#endif
}

class buffer
{
public:
	buffer(char* data, size_t size)
		: data_(data)
		, size_(size)
	{
	}

	char* data() const { return data_; }
	size_t size() const { return size_; }

private:
	char* data_;
	size_t size_;
};

namespace ssl
{

inline void init()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

inline void cleanup() { EVP_cleanup(); }

class context
{
public:
	enum method
	{
		tlsv12
	};

	context(method m)
		: context_(nullptr)
		, ssl_method_(nullptr)
		, verify_mode_(verify_peer)

	{

		switch (m)
		{
		case tlsv12:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			ssl_method_ = TLSv1_2_method();
			context_ = SSL_CTX_new(ssl_method_);
#else
			ssl_method_ = TLS_server_method();
			context_ = SSL_CTX_new(ssl_method_);
			SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION);
			SSL_CTX_set_max_proto_version(context_, TLS1_2_VERSION);
#endif
			break;
		}
	}

	~context()
	{
		SSL_CTX_free(context_);
		context_ = nullptr;
	}

	context(const context&) = delete;
	context(context&&) = delete;

	context& operator=(const context&) = delete;
	context& operator=(context&&) = delete;

	void use_certificate_chain_file(const char* path)
	{
		// SSL_CTX_set_ecdh_auto(context_, 1);
		int e = 0;
		/* Set the key and cert */
		if ((e = SSL_CTX_use_certificate_file(context_, path, SSL_FILETYPE_PEM)) <= 0)
		{
			char error[256];
			ERR_error_string_n(e, error, sizeof(error));

			throw std::runtime_error(error);
		}
	}

	void use_private_key_file(const char* path)
	{
		int e = 0;

		if ((SSL_CTX_use_PrivateKey_file(context_, path, SSL_FILETYPE_PEM)) <= 0)
		{
			char error[256];
			ERR_error_string_n(e, error, sizeof(error));

			throw std::runtime_error(error);
		}
	}

	enum verify_mode
	{
		verify_peer,
		verify_fail_if_no_peer_cert,
		verify_client_once
	};

	void set_verify_mode(verify_mode v) // network::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
	{
		verify_mode_ = v;
	}

	SSL_CTX* native() { return context_; }

private:
	SSL_CTX* context_;
	const SSL_METHOD* ssl_method_;
	verify_mode verify_mode_;
};

namespace stream_base
{
enum handshake_type
{
	client,
	server
};
}

template <class socket> class stream
{
public:
	stream(context& context)
		: context_(context)
		, lowest_layer_(0)
		, ssl_(nullptr)
	{
	}

	~stream()
	{
		if (ssl_) close();
	}

	stream(const stream& s) = delete;
	//		: context_(s.context_)
	//		, lowest_layer_(s.lowest_layer_)
	//		, ssl_(s.ssl_)
	//	{
	//	}
	stream& operator=(const stream&) = delete;
	stream& operator=(stream&&) = delete;

	stream(stream&& s) noexcept
		: context_(s.context_)
		, lowest_layer_(std::move(s.lowest_layer_))
		, ssl_(s.ssl_)
	{
		s.lowest_layer_.assign(static_cast<socket_t>(-1));
		s.ssl_ = nullptr;
	}

	void close()
	{
		SSL_free(ssl_);
		ssl_ = nullptr;
	}

	const socket& lowest_layer() const { return lowest_layer_; }

	socket& lowest_layer() { return lowest_layer_; }

	SSL* native() { return ssl_; }

	void handshake(stream_base::handshake_type)
	{
		ssl_ = SSL_new(context_.native());
		SSL_set_fd(ssl_, (int)(lowest_layer_.lowest_layer()));

		if (SSL_accept(ssl_) <= 0)
		{
			ERR_print_errors_fp(stderr);
		}
		else
		{
			SSL_CTX_set_mode(context_.native(), SSL_MODE_AUTO_RETRY);
		}
	}

private:
	context& context_;
	socket lowest_layer_;
	SSL* ssl_;
};

} // namespace ssl

namespace ip
{
using address = std::pair<std::string, std::uint16_t>;

inline address make_address(const std::string& url)
{
	std::string addr = url.substr(0, url.find_last_of(':'));
	std::uint16_t port = static_cast < std::uint16_t>(std::atoi(url.substr(url.find_last_of(':') + 1).c_str()));

	return address{ addr, port };
}

inline address make_address_from_name(const std::string& url)
{
	std::string addr = url.substr(0, url.find_last_of(':'));
	std::uint16_t port = static_cast < std::uint16_t>(atoi(url.substr(url.find_last_of(':') + 1).c_str()));

	return address{ addr, port };
}

inline address make_address_from_url(const std::string& url)
{
	// http://hostname.hostname.com:port/blablabla

	std::string protocol = url.substr(0, url.find_first_of(':'));

	std::string addr = url.substr(0, url.find_last_of(':'));
	std::uint16_t port = static_cast < std::uint16_t>(atoi(url.substr(url.find_last_of(':') + 1).c_str()));

	return address{ addr, port };
}

} // namespace ip

namespace tcp
{
enum protocol
{
	stream = SOCK_STREAM
};

enum options
{
	none,
	ipv6only,
	reuseaddr,
	reuseport,
	nolinger,
	nodelay,
	size
};

inline options operator|(options a, options b) { return options((static_cast<int>(a)) | (static_cast<int>(b))); }
inline options& operator|=(options& a, options b) { return reinterpret_cast<options&>(((reinterpret_cast<int&>(a)) |= (static_cast<int>(b)))); }
inline options operator&(options a, options b) { return options((static_cast<int>(a)) & (static_cast<int>(b))); }
inline options& operator&=(options& a, options b) { return reinterpret_cast<options&>((reinterpret_cast<int&>(a)) &= (static_cast<int>(b))); }
inline options operator~(options a) { return options(~(static_cast<int>(a))); }
inline options operator^(options a, options b) { return options((static_cast<int>(a)) ^ (static_cast<int>(b))); }
inline options& operator^=(options& a, options b) { return reinterpret_cast<options&>(((reinterpret_cast<int&>(a)) ^= (static_cast<int>(b)))); }

class socket
{
public:
	socket() = default;

	socket(socket_t s)
		: socket_(s)
	{
	}

	enum family
	{
		v4 = AF_INET,
		v6 = AF_INET6
	};

	socket(socket&& s) noexcept
		: socket_(s.socket_)
		, options_(s.options_)
	{
		s.socket_ = 0;
	}

	socket(const socket& s) noexcept
		: socket_(s.socket_)
		, options_(s.options_)
	{
	}

	socket& operator=(const socket& s) = default;
	socket& operator=(socket&& s) = default;
	//	{
	//		socket_ = s.socket_;
	//		options_ = options_;

	//		return *this;
	//	}

	~socket() { close(); };

	void assign(socket_t native_socket)
	{
		socket_ = native_socket;
		options_ = none;
	};

	void assign(socket&& socket)
	{
		socket_ = socket.lowest_layer();
		socket.lowest_layer() = static_cast<socket_t>(-1); // NOLINT
	};

	socket_t open(family fam, protocol prot)
	{
		socket_ = ::socket(fam, prot, 0);

		::setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&option_values_[options::ipv6only]), sizeof(std::int32_t));

		if (options_ & options::reuseaddr)
		{
			::setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&option_values_[options::reuseaddr]), sizeof(std::int32_t));
		}

		return socket_;
	}

	socket_t close()
	{
		if (socket_ && socket_ != -1)
		{
			::closesocket(socket_);
			socket_ = 0;
		}

		return socket_;
	}

	bool is_open() const { return socket_ != 0; }

	const socket_t& lowest_layer() const { return socket_; }

	socket_t& lowest_layer() { return socket_; }

	void set_options(options option, std::int32_t option_value)
	{
		options_ |= option;
		option_values_[option] = option_value;
	}

private:
	socket_t socket_{ static_cast<socket_t>(-1) };
	options options_{ none };
	std::int32_t option_values_[options::size] = {};
};

class endpoint
{
public:
	endpoint() noexcept
	{
		data_.v4.sin_family = static_cast<std::int16_t>(socket::family::v4);
		data_.v4.sin_port = 0;
		data_.v4.sin_addr.s_addr = INADDR_ANY;
	}

	endpoint(std::int32_t port, socket::family fam) noexcept
	{
		if (fam == socket::family::v6)
			std::memset(&endpoint::data_.v6, 0, sizeof(data_.v6));
		else
			std::memset(&endpoint::data_.v4, 0, sizeof(data_.v6));

		data_.base.sa_family = static_cast<std::int16_t>(fam);

		if (fam == socket::family::v6)
		{
			data_.v6.sin6_port = htons(static_cast <std::uint16_t>(port));
			data_.v6.sin6_addr = in6addr_any;
		}
		else
		{
			data_.v4.sin_port = htons(static_cast <std::uint16_t>(port));
			data_.v4.sin_addr.s_addr = INADDR_ANY;
		}
	}

	// endpoint(const std::string& ip, std::int16_t port) : socket_(0), protocol_(SOCK_STREAM) {}

	endpoint(sockaddr& addr)
	{
		using std::memcpy;
		memcpy(&data_, &addr, sizeof(sockaddr_storage));
	}

	endpoint(const endpoint&) = default;
	endpoint(endpoint&&) = default;
	endpoint& operator=(const endpoint&) = default;
	endpoint& operator=(endpoint&&) = default;

	virtual ~endpoint()
	{
		if (socket_.is_open()) socket_.close();
	};

	void close()
	{
		if (socket_.is_open()) socket_.close();
	}

	void connect(network::error_code& ec)
	{
		open(protocol_);
		int ret = ::connect(socket_.lowest_layer(), addr(), addr_size());

		if (ret == -1)
		{
			ec = network::error::connection_refused;
		}
		else
			ec = network::error::success;
	}

	sockaddr* addr()
	{
		if (data_.base.sa_family == AF_INET6)
			return reinterpret_cast<sockaddr*>(&data_.v6);
		else
			return reinterpret_cast<sockaddr*>(&data_.v4);
	};

	std::int32_t addr_size()
	{
		if (data_.base.sa_family == AF_INET6)
			return static_cast<std::int32_t>(sizeof(data_.v6));
		else
			return static_cast<std::int32_t>(sizeof(data_.v4));
	}

	void open(tcp::protocol protocol) { socket_.open(static_cast<network::tcp::socket::family>(data_.base.sa_family), protocol); }

	tcp::socket& socket() { return socket_; };

	std::string to_string()
	{
		char address[INET6_ADDRSTRLEN + 8];
		std::uint16_t port;

		if (data_.base.sa_family == AF_INET6)
		{
			inet_ntop(AF_INET6, &data_.v6.sin6_addr, address, INET6_ADDRSTRLEN);

			port = ntohs(data_.v6.sin6_port);
		}
		else
		{
			inet_ntop(AF_INET, &data_.v4.sin_addr, address, INET_ADDRSTRLEN);
			port = ntohs(data_.v4.sin_port);
		}

		return std::string(address + std::string(":") + std::to_string(port));
	}

protected:
	tcp::socket socket_;
	protocol protocol_{ protocol::stream };

protected:
	union data_union {
		sockaddr base;
		sockaddr_in v4;
		sockaddr_in6 v6;
		sockaddr_storage ss;
	} data_{};
};

/*
class v4 : public endpoint
{
public:
	v4(std::int16_t port) : endpoint(port)
	{
		data_.v4.sin_family = AF_INET;
		data_.v4.sin_port = htons(port);
		data_.v4.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	v4(const network::ip::address address) : sock_addr_({})
	{
		inet_pton(AF_INET, address.first.c_str(), &(sock_addr_.sin_addr));

		sock_addr_.sin_family = AF_INET;
		sock_addr_.sin_port = htons(address.second);
	}

	v4(const std::string& ip, std::int16_t port) : sock_addr_({})
	{
		inet_pton(AF_INET, ip.c_str(), &(sock_addr_.sin_addr));

		sock_addr_.sin_family = AF_INET;
		sock_addr_.sin_port = htons(port);
	}

	~v4()
	{
		if (socket_)
			::closesocket(socket_);
	}
private:
};
*/

class v6 : public endpoint
{
public:
	v6(std::int32_t port)
		: endpoint{ port, tcp::socket::family::v6 }
	{
	}

	v6(const std::string& ip, std::int32_t port)
		: endpoint{ port, tcp::socket::family::v6 }
	{
		inet_pton(AF_INET6, ip.c_str(), &(endpoint::data_.v6.sin6_addr));
	}

	v6(const network::ip::address address)
		: endpoint{ 0, tcp::socket::family::v6 }
	{
		inet_pton(AF_INET6, address.first.c_str(), &(endpoint::data_.v6.sin6_addr));

		endpoint::data_.v6.sin6_port = htons(address.second);
		;
	}

	tcp::protocol protocol() { return endpoint::protocol_; }

	void port(std::int32_t& value) { endpoint::data_.v6.sin6_port = htons(static_cast<std::uint16_t>(value)); }

private:
};

class resolver
{
public:
	using resolver_results = std::vector<network::tcp::endpoint>;

	resolver() = default;

	resolver_results& resolve(const std::string& hostname, const std::string& service)
	{
		addrinfo hints = { 0 };
		addrinfo* adresses = nullptr;
		addrinfo* item = nullptr;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		resolver_results_.clear();

		if (getaddrinfo(hostname.c_str(), service.c_str(), &hints, &adresses) != 0)
		{
			return resolver_results_;
		}

		for (item = adresses; item != nullptr; item = item->ai_next)
		{
			if (item->ai_addr->sa_family == AF_INET6)
			{
				resolver_results_.emplace_back(*item->ai_addr);
			}
			else
			{
				resolver_results_.emplace_back(*item->ai_addr);
			}
		}

		freeaddrinfo(adresses);

		return resolver_results_;
	}

private:
	resolver_results resolver_results_;
};

class acceptor
{
public:
	acceptor() = default;

	void open(tcp::protocol protocol) noexcept { protocol_ = protocol; }

	void bind(endpoint& endpoint, error_code& ec) noexcept
	{
		int ret = 0;
		endpoint_ = &endpoint;

		endpoint_->open(protocol_);

		ret = ::bind(endpoint_->socket().lowest_layer(), endpoint_->addr(), endpoint_->addr_size());

		if (ret == -1)
			ec = network::error::address_in_use;
		else
			ec = network::error::success;

		// ec.value = ret;
	}

	void listen() noexcept { ::listen(endpoint_->socket().lowest_layer(), 5); }

	void accept(socket& s, network::error_code& ec) noexcept
	{
		auto len = static_cast<socklen_t>(endpoint_->addr_size());

		auto client_socket = ::accept(endpoint_->socket().lowest_layer(), endpoint_->addr(), &len);
		s.assign(client_socket);

		if (client_socket == -1)
		{
			ec = network::error::interrupted;
		}
	}

	void accept(socket& s, network::error_code& ec, std::int16_t timeout) noexcept
	{
		auto len = static_cast<socklen_t>(endpoint_->addr_size());

		fd_set set{};
		timeval t{};
		int rv;

		FD_ZERO(&set); /* clear the set */
		FD_SET(endpoint_->socket().lowest_layer(), &set); /* add our file descriptor to the set */

		t.tv_sec = timeout;
		t.tv_usec = 0;

		rv = select(static_cast<int>(endpoint_->socket().lowest_layer()) + 1, &set, nullptr, nullptr, &t);

		if (rv == -1)
		{
			perror("select"); /* an error accured */
			return;
		}
		else if (rv == 0)
		{
			ec = network::error::operation_would_block;
		}
		else
		{
			auto client_socket = ::accept(endpoint_->socket().lowest_layer(), endpoint_->addr(), &len);
			s.assign(client_socket);

			if (client_socket == -1)
			{
				ec = network::error::interrupted;
			}
		}
	}

private:
	tcp::protocol protocol_;
	endpoint* endpoint_;
};
} // namespace tcp

inline error_code connect(tcp::socket& s, tcp::resolver::resolver_results& results)
{
	network::error_code ret = error::host_unreachable;

	for (auto& result : results)
	{
		result.connect(ret);

		s.assign(std::move(result.socket()));

		if (ret == error::success) break;
	}

	return ret;
}

inline std::int32_t read(const network::tcp::socket& s, const buffer& b) noexcept { return ::recv(s.lowest_layer(), b.data(), static_cast<int>(b.size()), 0); }

inline std::int32_t write(const network::tcp::socket& s, const buffer& b) noexcept { return ::send(s.lowest_layer(), b.data(), static_cast<int>(b.size()), 0); }

inline std::int32_t write(const network::tcp::socket& s, const std::string& str) noexcept { return ::send(s.lowest_layer(), str.data(), static_cast<int>(str.size()), 0); }

inline std::int32_t read(ssl::stream<tcp::socket>& s, const buffer& b) noexcept { return SSL_read(s.native(), b.data(), static_cast<int>(b.size())); }

inline std::int32_t write(ssl::stream<tcp::socket>& s, const buffer& b) noexcept { return SSL_write(s.native(), b.data(), static_cast<int>(b.size())); }

inline std::int32_t write(ssl::stream<tcp::socket>& s, const std::string& str) noexcept
{
	return SSL_write(s.native(), const_cast<char*>(str.data()), static_cast<int>(str.size()));
} // NOLINT

inline std::string get_client_info(network::ssl::stream<network::tcp::socket>& client_socket)
{
	sockaddr_in6 sa = { 0 };
	socklen_t sl = sizeof(sa);
	char c[INET6_ADDRSTRLEN];

	getpeername(client_socket.lowest_layer().lowest_layer(), reinterpret_cast<sockaddr*>(&sa), &sl);

	inet_ntop(AF_INET6, &(sa.sin6_addr), c, INET6_ADDRSTRLEN);

	return c;
}

inline std::string get_client_info(const network::tcp::socket& client_socket)
{
	sockaddr_in6 sa = { 0 };
	socklen_t sl = sizeof(sa);
	char c[INET6_ADDRSTRLEN];

	getpeername(client_socket.lowest_layer(), reinterpret_cast<sockaddr*>(&sa), &sl);

	inet_ntop(AF_INET6, &(sa.sin6_addr), c, INET6_ADDRSTRLEN);

	return c;
}

inline int tcp_nodelay(network::tcp::socket& s, int value)
{
	int reuseaddr = value;
	return ::setsockopt(s.lowest_layer(), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&reuseaddr), sizeof(reuseaddr)); // NOLINT
}

inline int reuse_address(network::tcp::socket& s, std::int32_t value)
{
	s.set_options(network::tcp::options::reuseaddr, value);
	return 0;
}

inline int ipv6only(network::tcp::socket& s, std::int32_t value)
{
	s.set_options(network::tcp::options::ipv6only, value);
	return 0;
}

inline int use_portsharding(network::tcp::socket& s, std::int32_t value)
{
	s.set_options(network::tcp::options::ipv6only, value);
	return 0;
}

inline int no_linger(network::tcp::socket& s, int value)
{
	// No linger
	linger linger_{};
	memset(&linger_, 0, sizeof(linger));

	if (value)
	{
		linger_.l_onoff = 0;
		linger_.l_linger = 0;
	}
	else
	{
		linger_.l_onoff = 1;
		linger_.l_linger = 5;
	}

	int ret = ::setsockopt(s.lowest_layer(), SOL_SOCKET, SO_LINGER, reinterpret_cast<char*>(&linger_), sizeof(linger)); // NOLINT

	return ret;
}

inline int timeout(network::tcp::socket& s, int value)
{
#if defined(_WIN32)
	DWORD timeout_value = static_cast<DWORD>(value) * 1000;
	int ret = ::setsockopt(s.lowest_layer(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout_value), sizeof(timeout_value)); // NOLINT
#else
	timeval timeout{};
	timeout.tv_sec = value;
	timeout.tv_usec = 0;
	int ret = setsockopt(s.lowest_layer(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif

	return ret;
}

inline void closesocket(network::tcp::socket& client_socket) { ::closesocket(client_socket.lowest_layer()); }

inline void closesocket(network::ssl::stream<network::tcp::socket>& client_socket)
{
	client_socket.close();
	::closesocket(client_socket.lowest_layer().lowest_layer());
}

inline void shutdown(network::tcp::socket& client_socket, int how) { ::shutdown(client_socket.lowest_layer(), how); }

enum shutdown_type
{
	shutdown_receive = 0,
	shutdown_send,
	shutdown_both
};

inline void shutdown(network::ssl::stream<network::tcp::socket>& client_socket, shutdown_type how)
{
	::shutdown(client_socket.lowest_layer().lowest_layer(), static_cast<int>(how));
}

} // namespace network
