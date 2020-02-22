#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <numeric>
#include <unordered_map>

#include "http_basic.h"

//#include "http_asio.h"
#include "neolm.h"

#include "process_utils.h"

#include <vector>

namespace nstd
{
template <typename T> class inline_vector_impl
{
private:
	T* begin_;
	T* end_;
	size_t capacity_;

public:
	inline_vector_impl(T* begin, T* end, size_t capacity) : begin_(begin), end_(end), capacity_(capacity){};
};

template <class T, std::int16_t S> class inline_vector : public inline_vector_impl<T>
{
private:
	typename std::aligned_storage<sizeof(T), alignof(T)>::type buffer_[S];
	size_t size_;

public:
	inline_vector() : inline_vector_impl(reinterpret_cast<T*>(&buffer_), reinterpret_cast<T*>(&buffer_[S]), S) 
	{
	}

	// Delete objects from aligned storage
	~inline_vector()
	{
		for (std::size_t pos = 0; pos < size_; ++pos)
		{
			// note: needs std::launder as of C++17
			reinterpret_cast<T*>(&buffer_[pos])->~T();
		}
	}


	// Create an object in aligned storage
	template <typename... Args> void emplace_back(Args&&... args)
	{
		if (size_ >= S) // possible error handling
			throw std::bad_alloc{};

		// construct value in memory of aligned storage
		// using inplace operator new
		new (&buffer_[size_]) T(std::forward<Args>(args)...);
		++size_;
	}

	// Access an object in aligned storage
	const T& operator[](std::size_t pos) const
	{
		// note: needs std::launder as of C++17
		return *reinterpret_cast<const T*>(&buffer_[pos]);
	}
};

} // namespace nstd
using json = nlohmann::json;

int main()
{
	nstd::inline_vector<size_t, 10> v;

	for (int x =0; x!=9; x++)
		v.emplace_back(x);



	network::init();
	network::ssl::init();

	for (auto i = 0; i != 100; i++)

	{
		neolm::license_manager<http::basic::threaded::server> license_server{
			http::configuration{ { "http_server_identification", "mir_http/8.0.01" },
								 { "http_listen_address", "::0" },
								 { "http_listen_port_begin", "3000" },
								 { "https_enable", "false" },
								 { "private_base", "/_internal" },
								 { "log_file", "cerr" },
								 { "log_level", "none" },
								 { "upstream_node_type", "" },
								 { "upstream_node_nginx-endpoint", "nlbavlflex01.infor.com:7777" },
								 { "upstream_node_nginx-group", "bshell-workers" } },
			"/projects/neolm_licenses/"
		};

		license_server.start_server();

		license_server.run();
	}
}
