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

namespace hib
{

template <class T, std::uint8_t S> class vector
{
public:
	using size_type = size_t;
	using difference_type = ptrdiff_t;
	using value_type = T;
	using iterator = T*;
	using const_iterator = const T*;

	using const_reverse_iterator = std::reverse_iterator<const_iterator>;
	using reverse_iterator = std::reverse_iterator<iterator>;

	using reference = T&;
	using const_reference = const T&;
	using pointer = T*;
	using const_pointer = const T*;

private:
	T* begin_;
	T* end_;
	size_t capacity_;
	size_t size_;

	struct __data
	{
		union {

			pointer __pointer_;
			typename std::aligned_storage<sizeof(value_type), alignof(value_type)>::type __inline_[S];
		};
	};

	__data data_{};

public:
	vector()
		: begin_(reinterpret_cast<pointer>(&data_.__inline_[0]))
		, end_(reinterpret_cast<pointer>(&data_.__inline_[S]))
		, capacity_(S)
		, size_(0)
	{
	}

	vector(const vector& rhs)
		: begin_(reinterpret_cast<pointer>(&data_.__inline_[0]))
		, end_(reinterpret_cast<pointer>(&data_.__inline_[S]))
		, capacity_(S)
		, size_(0)
	{
		assign(rhs.begin(), rhs.end());
	}

	vector(vector&& rhs)
		: begin_(reinterpret_cast<pointer>(&data_.__inline_[0]))
		, end_(reinterpret_cast<pointer>(&data_.__inline_[S]))
		, capacity_(S)
		, size_(0)
	{
		assign(rhs.begin(), rhs.end());
	}

	vector(std::initializer_list<T> list)
		: begin_(reinterpret_cast<pointer>(&data_.__inline_[0]))
		, end_(reinterpret_cast<pointer>(&data_.__inline_[S]))
		, capacity_(S)
		, size_(0)
	{
		assign(list.begin(), list.end());
	}

	// Delete objects from aligned storage
	~vector() { clear(); }

	void clear()
	{
		for (std::size_t pos = 0; pos < size(); ++pos)
		{
			// note: needs std::launder as of C++17
			reinterpret_cast<T*>(&data_.__inline_[pos])->~T();
		}
	}

	void resize(size_type s)
	{
		if (s <= S)
		{
		}
		else
		{
			// increase space
			auto new_storage = static_cast<T*>(std::malloc(s * sizeof(value_type)));
			std::uninitialized_copy(std::make_move_iterator(begin()), std::make_move_iterator(end()), new_storage);

			for (std::size_t pos = 0; pos < size(); ++pos)
			{
				// note: needs std::launder as of C++17
				reinterpret_cast<T*>(&begin()[pos])->~T();
			}
			begin_ = new_storage;
			end_ = new_storage + size();
			capacity_ = s;
		}
	}

	/// Add the specified range to the end of the SmallVector.
	template <
		typename in_iter,
		typename = typename std::enable_if<std::is_convertible<
			typename std::iterator_traits<in_iter>::iterator_category,
			std::input_iterator_tag>::value>::type>
	void append(in_iter in_start, in_iter in_end)
	{
		size_type num_inputs = std::distance(in_start, in_end);
		if (num_inputs > this->capacity() - this->size()) resize(this->size() + num_inputs);

		std::uninitialized_copy(in_start, in_end, this->end());
		this->set_size(this->size() + num_inputs);
	}

	/// Append \p NumInputs copies of \p Elt to the end.
	void append(size_type NumInputs, const T& Elt)
	{
		if (NumInputs > this->capacity() - this->size()) this->grow(this->size() + NumInputs);

		std::uninitialized_fill_n(this->end(), NumInputs, Elt);
		this->set_size(this->size() + NumInputs);
	}

	void append(std::initializer_list<T> IL) { append(IL.begin(), IL.end()); }

	void assign(size_type count, const T& value)
	{
		clear();
		if (this->capacity() < count) this->resize(count);
		this->set_size(count);
		std::uninitialized_fill(begin(), end(), value);
	}

	template <
		typename in_iter,
		typename = typename std::enable_if<std::is_convertible<
			typename std::iterator_traits<in_iter>::iterator_category,
			std::input_iterator_tag>::value>::type>
	void assign(in_iter in_start, in_iter in_end)
	{
		clear();
		append(in_start, in_end);
	}

	void assign(std::initializer_list<T> IL)
	{
		clear();
		append(IL);
	}
	template <typename... Args> void emplace_back(Args&&... args)
	{
		if (size() >= capacity())
		{
			resize(size() << 2);
		}

		new (begin_ + size()) T(std::forward<Args>(args)...);
		set_size(size() + 1);
	}

	////// Access an object in aligned storage
	////const T& operator[](std::size_t pos) const
	////{
	////	// note: needs std::launder as of C++17
	////	return *reinterpret_cast<const T*>(&buffer_[pos]);
	////}

	size_t size() const { return size_; }
	size_t capacity() const { return capacity_; }
	bool empty() const { return !size_; }

	//// forward iterator creation methods.
	iterator begin() { return (iterator)begin_; }
	const_iterator begin() const { return (const_iterator)begin_; }
	iterator end() { return begin() + size(); }
	const_iterator end() const { return begin() + size(); }

	//// reverse iterator creation methods.
	reverse_iterator rbegin() { return reverse_iterator(end()); }
	const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }
	reverse_iterator rend() { return reverse_iterator(begin()); }
	const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }

	size_type size_in_bytes() const { return size() * sizeof(T); }
	size_type max_size() const { return size_type(-1) / sizeof(T); }

	size_t capacity_in_bytes() const { return capacity() * sizeof(T); }

	/// Return a pointer to the vector's buffer, even if empty().
	pointer data() { return pointer(begin()); }
	/// Return a pointer to the vector's buffer, even if empty().
	const_pointer data() const { return const_pointer(begin()); }

	reference operator[](size_type idx)
	{
		assert(idx < size());
		return begin()[idx];
	}
	const_reference operator[](size_type idx) const
	{
		assert(idx < size());
		return begin()[idx];
	}

	reference front()
	{
		assert(!empty());
		return begin()[0];
	}

	const_reference front() const
	{
		assert(!empty());
		return begin()[0];
	}

	reference back()
	{
		assert(!empty());
		return end()[-1];
	}

	const_reference back() const
	{
		assert(!empty());
		return end()[-1];
	}

protected:
	void set_size(size_type s) { size_ = s; }
};

} // namespace std

using json = nlohmann::json;

int main()
{
	hib::vector<std::int16_t, 10> v1;

	for (std::int16_t x = 0; x != 9; x++)
		v1.emplace_back(x);

	for (auto& s : v1)
	{
		std::cout << std::to_string(s) << std::endl;
	}

	hib::vector<std::string, 2> v2{};

	for (std::int16_t x = 0; x != 9; x++)
		v2.emplace_back(std::to_string(x));

	for (auto& s : v2)
	{
		std::cout << s << std::endl;
	}

	auto v3{ v2 };
	auto v4{ std::move(v3) };

	hib::vector<std::string, 20> v5{ 
		"aa",
		"bb"
		"cc" 
	};

	auto x = v5.data();

	std::cout << *x << std::endl;

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
