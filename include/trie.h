#include <iterator>
#include <map>
#include <memory>
#include <stack>
#include <string>


template <typename T> class trie
{
	struct node
	{
		std::map<T, std::unique_ptr<node>> link;
		bool terminal;
		T key;

	public:
		node(T key)
			: terminal(false)
			, key(key)
		{
		}
	};
	std::unique_ptr<node> root;

public:
	trie()
		: root(new node(T()))
	{
	}
	void add(const std::basic_string<T>& s);
	void remove(const std::basic_string<T>& s);
	typename std::basic_string<T>::size_type match(const std::basic_string<T>& s, bool require_terminal = true) const;
};

template <typename T> void trie<T>::add(const std::basic_string<T>& s)
{
	auto it = root.get();

	for (auto c : s)
	{
		auto& link = it->link[c];
		if (!link)
		{
			link.reset(new node(c));
		}
		it = link.get();
	}

	it->terminal = true;
}
template <typename T> void trie<T>::remove(const std::basic_string<T>& s)
{
	auto it = root.get();
	std::stack<decltype(it)> bak;

	for (auto c : s)
	{
		auto link = it->link.find(c);
		if (link == std::end(it->link))
		{
			return; // No match
		}
		bak.push(it);
		it = link->second.get();
	}

	it->terminal = false;
	if (it->link.size() == 0)
	{

		T key = it->key;

		while (!bak.empty() && bak.top()->link.size() <= 1 && !bak.top()->terminal)
		{
			key = bak.top()->key;
			bak.pop();
		}
		if (!bak.empty())
		{
			// Average case: Trim the tail from the parent's links
			bak.top()->link.erase(key);
		}
		else
		{
			// Edge case: This was the last path in the trie
			root->link.clear();
		}
	}
}
template <typename T> typename std::basic_string<T>::size_type trie<T>::match(const std::basic_string<T>& s, bool require_terminal) const
{
	auto it = root.get();
	// Follow the path until the end of the string or a mismatch
	for (auto end = std::begin(s); end != std::end(s); ++end)
	{
		auto link = it->link.find(*end);
		if (link == std::end(it->link))
		{
			// The path was exhausted while searching
			return std::distance(s.begin(), end);
		}
		it = link->second.get();
	}
	if (!require_terminal || it->terminal)
	{
		// The path was matched completely
		return std::basic_string<T>::npos;
	}
	return s.size(); // A prefix was matched
}