#pragma once
#include <algorithm>
#include <cassert>
#include <memory>

namespace hyb
{

template <class T, std::uint8_t S> class basic_string
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
	size_t size_;
	size_t capacity_;
	bool inline_used_;

	struct _data
	{
		union {
			pointer pointer_;
			T inline_store_[S];
		};
	};

	_data data_{};

public:
	basic_string() : begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0) {}

	basic_string(const char* str) : begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0)
	{
		assign(str, str + std::strlen(str));
	}

	basic_string(const std::string& str)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0)
	{
		assign(str.begin(), str.end());
	}

	basic_string(std::string&& str) : begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0)
	{
		assign(str.begin(), str.end());
	}

	basic_string(const basic_string& rhs)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0), inline_used_(true)
	{
		assign(rhs.begin(), rhs.end());
	}

	basic_string(basic_string&& rhs)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0), inline_used_(true)
	{
		assign(rhs.begin(), rhs.end());
	}

	basic_string(std::initializer_list<T> list)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0), inline_used_(true)
	{
		assign(list.begin(), list.end());
	}

	~basic_string() { clear(); }

	void clear()
	{
		auto old_size = size();

		if (!empty())
		{

			for (std::size_t pos = 0; pos < old_size; ++pos)
			{
				reinterpret_cast<T*>(&begin()[pos])->~T();
			}

			// if (!inline_used_) delete data_.pointer_;

			begin_ = reinterpret_cast<pointer>(&data_.inline_store_[0]);
			capacity_ = S;
			size_ = 0;
			inline_used_ = true;
		}
	}

	void resize(size_type s)
	{
		if (s <= S && inline_used_)
		{
		}
		else if (s <= S)
		{
			// move data back from external storage
			std::uninitialized_copy(
				std::make_move_iterator(begin()),
				std::make_move_iterator(end()),
				reinterpret_cast<T*>(&data_.inline_store_));

			for (std::size_t pos = 0; pos < size(); ++pos)
			{
				reinterpret_cast<T*>(&begin()[pos])->~T();
			}
			begin_ = reinterpret_cast<T*>(&data_.inline_store_);
			capacity_ = S;
			inline_used_ = true;
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
			data_.pointer_ = new_storage;
			inline_used_ = false;
			capacity_ = s;
		}
	}

	/// Add the specified range to the end of the Smallbasic_string.
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
		if (NumInputs > this->capacity() - this->size()) resize(this->size() + NumInputs);

		std::uninitialized_fill_n(this->end(), NumInputs, Elt);
		this->set_size(this->size() + NumInputs);
	}

	/// Append \p NumInputs copies of \p Elt to the end.
	void append(const char* str, size_t length)
	{
		if (length > this->capacity() - this->size()) resize(this->size() + length);

		std::uninitialized_copy(str, str + length, begin());
		this->set_size(this->size() + length);
	}

	/// Append \p NumInputs copies of \p Elt to the end.
	void append(const basic_string& s)
	{
		if (s.size() > this->capacity() - this->size()) resize(this->size() + s.size());

		std::uninitialized_copy(s.cbegin(), s.cend(), end());

		this->set_size(this->size() + s.size());
	}

	static const size_type npos = std::string::npos;

	size_type find(const basic_string& str, size_type pos = 0) const
	{
		size_type ret = npos;

		for (size_type i = pos; i < size(); ++i)
		{
			auto c1 = *(begin() + i);

			if (c1 == *(str.begin()))
			{
				ret = i;
				size_type j = 0;
				for (auto c2 : str)
				{
					c1 = *(begin() + j);

					if (c1 == c2)
						break;
					else
						ret = npos;
				}
			}
		}

		return ret;
	} // TODO

	constexpr size_type find_last_not_of(char c, size_type pos = npos) const
	{
		size_type ret = npos;
		for (size_type i = (pos == !npos ? pos : size()); i >= 0; --i)
		{
			if (*(begin() + i) == c)
			{
				ret = i;
				break;
			}
		}

		return ret;
	} // TODO

	constexpr size_type find_last_not_of(const char* str, size_type pos = npos) const
	{
		size_type ret = npos;
		for (size_type i = (pos == !npos ? pos : size()-1); i != 0; --i)
		{

			size_type j = 0;
			char c = *(begin() + i);

			for (; str[j] != 0; j++)
			{
				if (c == str[j])
				{
					break;
				}
			}

			if (str[j] == 0)
			{
				ret = i+1;
				break;
			}
		}

		return ret;
	}

	constexpr size_type find_last_of(const char* str, size_type pos = npos) const { return 0; }

	basic_string substr(size_t first, size_t last) const
	{
		basic_string ret{};
		ret.assign(begin() + first, begin() + last);
		return ret;
	} // TODO

	const basic_string& operator=(const basic_string& rhs)
	{
		assign(rhs.begin(), rhs.end());
		return *this;
	}

	/// Append \p NumInputs copies of \p Elt to the end.
	void append(const char* str) { append(str, std::strlen(str)); }

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

		new (begin() + size()) T(std::forward<Args>(args)...);
		set_size(size() + 1);
	}

	void push_back(const T value)
	{
		if (size() >= this->capacity()) resize(size() << 2);

		::new (begin() + size()) T(value);

		this->set_size(this->size() + 1);
	}

	// void push_back(T&& value)
	//{
	//	if (size() >= capacity()) resize(size() << 2);

	//	::new ((void*)this->end()) T(::std::move(value));

	//	this->set_size(this->size() + 1);
	//}

	iterator erase(iterator position)
	{
		assert(position >= begin() && "Iterator to erase is out of bounds.");
		assert(position < end() && "Erasing at past-the-end iterator.");

		iterator i = position;
		// Shift all elts down one.
		std::move(i + 1, end(), i);
		// Drop the last elt.
		pop_back();
		return (i);
	}

	iterator erase(iterator first, iterator last)
	{
		assert(first >= begin() && "Range to erase is out of bounds.");
		assert(first <= last && "Trying to erase invalid range.");
		assert(last <= end() && "Trying to erase past the end.");

		iterator n = first;
		// Shift all elts down.
		iterator i = std::move(last, end(), first);
		// Drop the last elts.
		destroy_range(i, end());
		this->set_size(i - begin());
		return (n);
	}

	void pop_back()
	{
		this->set_size(this->size() - 1);
		this->end()->~T();
	}

	size_t size() const { return size_; }
	size_t capacity() const { return capacity_; }
	bool empty() const { return !size_; }

	//// forward iterator creation methods.
	iterator begin() { return (iterator)begin_; }
	const_iterator begin() const { return (const_iterator)begin_; }
	iterator end() { return begin() + size(); }
	const_iterator end() const { return begin() + size(); }

	//// forward iterator creation methods.
	const_iterator cbegin() const { return (const_iterator)begin_; }
	const_iterator cend() const { return cbegin() + size(); }

	//// reverse iterator creation methods.
	reverse_iterator rbegin() { return reverse_iterator(end()); }
	const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }
	reverse_iterator rend() { return reverse_iterator(begin()); }
	const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }

	size_type size_in_bytes() const { return size() * sizeof(T); }
	size_type max_size() const { return size_type(-1) / sizeof(T); }

	size_t capacity_in_bytes() const { return capacity() * sizeof(T); }

	/// Return a pointer to the basic_string's buffer, even if empty().
	pointer data() { return pointer(begin()); }
	/// Return a pointer to the basic_string's buffer, even if empty().
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

template <class T, std::int8_t S>
basic_string<T, S> operator+(const basic_string<T, S>& lhs, const basic_string<T, S>& rhs)
{
	basic_string<T, S> ret{ lhs };
	ret.append(rhs.begin(), rhs.end());

	return ret;
}

template <class T, std::int8_t S>
std::basic_ostream<T>& operator<<(std::basic_ostream<T>& os, const hyb::basic_string<T, S>& str)
{
	os << str.data();
	return os;
}

template <class T, std::int8_t S>
bool operator==(const hyb::basic_string<T, S>& lhs, const hyb::basic_string<T, S>& rhs) noexcept
{
	if (lhs.size() == rhs.size())
		for (hyb::basic_string<T, S>::size_type i = 0; i != lhs.size(); ++i)
		{
			if (lhs[i] != rhs[i]) return false;
		}
	else
		return false;

	return true;
}

template <class T, std::int8_t S> bool operator==(const hyb::basic_string<T, S>& lhs, const std::string& rhs) noexcept
{
	if (lhs.size() == rhs.size())
		for (hyb::basic_string<T, S>::size_type i = 0; i != lhs.size(); ++i)
		{
			if (lhs[i] != rhs[i]) return false;
		}
	else
		return false;

	return true;
}

template <class T, std::int8_t S> bool operator==(const std::string& lhs, const hyb::basic_string<T, S>& rhs) noexcept
{
	if (lhs.size() == rhs.size())
		for (hyb::basic_string<T, S>::size_type i = 0; i != lhs.size(); ++i)
		{
			if ((lhs[i]) != (rhs[i])) return false;
		}
	else
		return false;

	return true;
}

template <class T, std::int8_t S>
bool operator!=(const hyb::basic_string<T, S>& lhs, const hyb::basic_string<T, S>& rhs) noexcept
{
	return !(lhs == rhs);
}

using string = basic_string<char, 64>;

// ofstream <<
// + operator

} // namespace hyb
