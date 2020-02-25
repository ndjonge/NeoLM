#pragma once
#include <cassert>
#include <memory>

namespace hyb
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
	vector() : begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0) {}

	vector(const vector& rhs)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0), inline_used_(true)
	{
		assign(rhs.begin(), rhs.end());
	}

	vector(vector&& rhs)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0), inline_used_(true)
	{
		assign(rhs.begin(), rhs.end());
	}

	vector(std::initializer_list<T> list)
		: begin_(reinterpret_cast<pointer>(&data_.inline_store_[0])), capacity_(S), size_(0), inline_used_(true)
	{
		assign(list.begin(), list.end());
	}

	~vector() { clear(); }

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
		if (NumInputs > this->capacity() - this->size()) resize(this->size() + NumInputs);

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

		new (begin() + size()) T(std::forward<Args>(args)...);
		set_size(size() + 1);
	}

	void push_back(const T& value)
	{
		if (size() >= this->capacity()) resize(size << 2);

		::new ((void*)this->end()) T(value);

		this->set_size(this->size() + 1);
	}

	void push_back(T&& value)
	{
		if (size() >= capacity()) resize(size() << 2);

		::new ((void*)this->end()) T(::std::move(value));

		this->set_size(this->size() + 1);
	}

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

} // namespace hyb
