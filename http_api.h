#pragma once

#include <regex>

#include "http_message.h"

namespace http
{
class session_handler;

namespace api
{
	namespace path2regex
	{
		const std::regex PATH_REGEXP = std::regex{ "((\\\\.)|(([\\/.])?(?:(?:\\:(\\w+)(?:\\(((?:\\\\.|[^\\\\()])+)\\))?|\\(((?:\\\\.|[^\\\\()])+)\\))([+*?])?|(\\*))))" };

		struct token
		{
			std::string name{};
			std::string prefix{};
			std::string delimiter{};
			std::string pattern{};

			bool optional{ false };
			bool repeat{ false };
			bool partial{ false };
			bool asterisk{ false };
			bool is_string{ false };

			void set_string_token(const std::string& name_)
			{
				name = name_;
				is_string = true;
			}
		}; //< struct Token

		using keys = std::vector<token>;
		using tokens = std::vector<token>;
		using options = std::map<std::string, bool>;

		std::vector<token> parse(const std::string& str)
		{
			if (str.empty()) return {};

			tokens tokens;
			int key = 0;
			size_t index = 0;
			std::string path = "";
			std::smatch res;

			for (std::sregex_iterator i = std::sregex_iterator{ str.begin(), str.end(), PATH_REGEXP }; i != std::sregex_iterator{}; ++i)
			{

				res = *i;

				std::string m = res[0]; // the parameter, f.ex. /:test
				std::string escaped = res[2];
				size_t offset = res.position();

				// JS: path += str.slice(index, offset); from and included index to and included offset-1
				path += str.substr(index, (offset - index)); // from index, number of chars: offset - index

				index = offset + m.size();

				if (!escaped.empty())
				{
					path += escaped[1]; // if escaped == \a, escaped[1] == a (if str is "/\\a" f.ex.)
					continue;
				}

				std::string next = ((size_t)index < str.size()) ? std::string{ str.at(index) } : "";

				std::string prefix = res[4]; // f.ex. /
				std::string name = res[5]; // f.ex. test
				std::string capture = res[6]; // f.ex. \d+
				std::string group = res[7]; // f.ex. (users|admins)
				std::string modifier = res[8]; // f.ex. ?
				std::string asterisk = res[9]; // * if path is /*

											   // Push the current path onto the tokens
				if (!path.empty())
				{
					token stringToken;
					stringToken.set_string_token(path);
					tokens.push_back(stringToken);
					path = "";
				}

				bool partial = (!prefix.empty()) && (!next.empty()) && (next != prefix);
				bool repeat = (modifier == "+") || (modifier == "*");
				bool optional = (modifier == "?") || (modifier == "*");

				std::string delimiter = (!prefix.empty()) ? prefix : "/";
				std::string pattern;

				if (!capture.empty())
					pattern = capture;
				else if (!group.empty())
					pattern = group;
				else
					pattern = (!asterisk.empty()) ? ".*" : ("[^" + delimiter + "]+?");

				token t;
				t.name = (!name.empty()) ? name : std::to_string(key++);
				t.prefix = prefix;
				t.delimiter = delimiter;
				t.optional = optional;
				t.repeat = repeat;
				t.partial = partial;
				t.asterisk = (asterisk == "*");
				t.pattern = pattern;
				t.is_string = false;
				tokens.push_back(t);
			}

			// Match any characters still remaining
			if ((size_t)index < str.size()) path += str.substr(index);

			// If the path exists, push it onto the end
			if (!path.empty())
			{
				token stringToken;
				stringToken.set_string_token(path);
				tokens.push_back(stringToken);
			}

			return tokens;
		}

		// Creates a regex based on the given tokens and options (optional)
		std::regex tokens_to_regex(const tokens& tokens, const options& options_ = options{})
		{
			if (tokens.empty()) return std::regex{ "" };

			// Set default values for options:
			bool strict = false;
			bool sensitive = false;
			bool end = true;

			if (!options_.empty())
			{
				auto it = options_.find("strict");
				strict = (it != options_.end()) ? options_.find("strict")->second : false;

				it = options_.find("sensitive");
				sensitive = (it != options_.end()) ? options_.find("sensitive")->second : false;

				it = options_.find("end");
				end = (it != options_.end()) ? options_.find("end")->second : true;
			}

			std::string route = "";
			token lastToken = tokens[tokens.size() - 1];
			std::regex re{ "(.*\\/$)" };
			bool endsWithSlash = lastToken.is_string && std::regex_match(lastToken.name, re);
			// endsWithSlash if the last char in lastToken's name is a slash

			// Iterate over the tokens and create our regexp string
			for (size_t i = 0; i < tokens.size(); i++)
			{
				token token = tokens[i];

				if (token.is_string)
				{
					route += token.name;
				}
				else
				{
					std::string prefix = token.prefix;
					std::string capture = "(?:" + token.pattern + ")";

					if (token.repeat) capture += "(?:" + prefix + capture + ")*";

					if (token.optional)
					{

						if (!token.partial)
							capture = "(?:" + prefix + "(" + capture + "))?";
						else
							capture = prefix + "(" + capture + ")?";
					}
					else
					{
						capture = prefix + "(" + capture + ")";
					}

					route += capture;
				}
			}

			// In non-strict mode we allow a slash at the end of match. If the path to
			// match already ends with a slash, we remove it for consistency. The slash
			// is valid at the end of a path match, not in the middle. This is important
			// in non-ending mode, where "/test/" shouldn't match "/test//route".

			if (!strict)
			{
				if (endsWithSlash) route = route.substr(0, (route.size() - 1));

				route += "(?:\\/(?=$))?";
			}

			if (end)
			{
				route += "$";
			}
			else
			{
				// In non-ending mode, we need the capturing groups to match as much as
				// possible by using a positive lookahead to the end or next path segment
				if (!(strict && endsWithSlash)) route += "(?=\\/|$)";
			}

			if (sensitive) return std::regex{ "^" + route };

			return std::regex{ "^" + route, std::regex_constants::ECMAScript | std::regex_constants::icase };
		}

		void tokens_to_keys(const tokens& tokens, keys& keys)
		{
			for (const auto& token : tokens)
				if (!token.is_string) keys.push_back(token);
		}

		std::regex path_to_regex(const std::string& path, keys& keys, const options& options_ = options{})
		{
			tokens all_tokens = parse(path);
			tokens_to_keys(all_tokens, keys); // fill keys with relevant tokens
			return tokens_to_regex(all_tokens, options_);
		}

		std::regex path_to_regex(const std::string& path, const options& options_ = options{}) { return tokens_to_regex(parse(path), options_); }


	} // namespace path_to_regex

	template<class function_t = std::function<bool(http::session_handler& session)>>
	class route
	{
	public:
		route(const std::string& path, function_t endpoint)
			: path_(path)
			, endpoint_(endpoint)
		{
			expr_ = path_to_regex(path_, keys_);
		};

		std::string path_;
		function_t endpoint_;

		path2regex::keys keys_;
		std::regex expr_;

		size_t hits_{ 0U };
	};

	bool operator < (const route<>& lhs, const route<>& rhs) noexcept {
		return lhs.hits_ < rhs.hits_;
	}


	template <class function_t = std::function<bool(http::session_handler& session)>> class router
	{
	public:
		router()
			: doc_root("/var/www"){};

		router(const std::string& doc_root)
			: doc_root_(doc_root){};

		//router.on_get("", [](http::session_handler& session) {});

		void on_get_2(const std::string& route, function_t api_method)
		{ 
			api_router_table_regex["GET"].emplace_back(api::route<>(route, api_method));
		};

		void on_option(const std::string path, function_t api_method) { this->add_route("OPTION", path, api_method); };
		void on_get(const std::string path, function_t api_method) { this->add_route("GET", path, api_method); };
		void on_head(const std::string path, function_t api_method) { this->add_route("HEAD", path, api_method); };
		void on_post(const std::string path, function_t api_method) { this->add_route("POST", path, api_method); };
		void on_put(const std::string path, function_t api_method) { this->add_route("PUT", path, api_method); };
		void on_update(const std::string path, function_t api_method) { this->add_route("UPDATE", path, api_method); };
		void on_delete(const std::string path, function_t api_method) { this->add_route("DELETE", path, api_method); };
		void on_patch(const std::string path, function_t api_method) { this->add_route("PATCH", path, api_method); };

		void add_route(const std::string& http_request_method, const std::string& http_request_uri, function_t api_method)
		{
			std::string key{ http_request_method + ":" + http_request_uri };

			api_router_table.insert(std::make_pair(key, api_method));
		}

		bool call(http::session_handler& session)
		{
			std::string key{ session._request().method() + ":" + session._request().target() };

			auto i = api_router_table.find(key);

			if (i != api_router_table.end())
			{
				auto ret = api_router_table[key](session);
				printf("http::api::router::route %s : reply will return : %s", key.c_str(), http::status::to_string(session._reply().status_));
				return ret;
			}
			else
			{
				session._request().target() = doc_root_ + session._request().target();

				if (fs::exists(session._request().target()))
				{
					printf("http::api::router::route %s reply will return : %s", session._request().target().c_str(), http::status::to_string(session._reply().status_));
					return true;
				}
				else
				{
					session._reply().status_ = http::status::not_found;
					printf("http::api::router::route %s : not found, reply will return : %s", key.c_str(), http::status::to_string(session._reply().status_));
					return false;
				}
			}
		}

	protected:
		std::string doc_root_;
		std::map<const std::string, function_t> api_router_table;

		std::map<const std::string, std::vector<api::route<>>> api_router_table_regex;

	};
} // namespace api
} // namespace http