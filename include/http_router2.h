#include <iterator>
#include <map>
#include <memory>
#include <stack>
#include <string>

#include "http_basic.h"

void test()
{
	http::api::router<> t("a");

	int x = 0;
	for (auto n = 0; n != 10; n++)
		for (auto i = 0; i != 10; i++)
			for (auto k = 0; k != 10; k++)
				for (auto f = 0; f != 100; f++)
				{

					t.on_get(
						std::move(
							"/v-" + std::to_string(n) + "/service-" + std::to_string(i) + "/subservice-" + std::to_string(k) + "/route/test-" + std::to_string(x++) + "/:test"),
						[](http::session_handler& session, const http::api::params& params) {
							const auto& test = params.get("test");

							if (test.empty())
							{
								session.response().result(http::status::bad_request);
							}
							else
							{
								session.response().body() = "test:" + test;
								session.response().result(http::status::ok);
							}
						});
				}

	http::api::params p;

	auto route_result = t.match_route(http::method::get, "/v1/service1/subservice1/resource1/subresource1", p);

	http::configuration c{ {} };
	http::session_handler s(c);

	if (route_result.result() == http::api::router_match::match_found) route_result.matched_route().endpoint()(s, p);
}



//namespace old
//{
//
//template <typename R = route_function_t> class route1
//{
//public:
//	route1(http::method::method_t method, const std::string& route, const R& endpoint)
//		: method_(method)
//		, endpoint_(endpoint)
//	{
//		size_t b = route.find_first_of('/');
//		size_t e = route.find_first_of('/', b + 1);
//		size_t token = 0;
//
//		for (token = 0; b != std::string::npos; token++)
//		{
//			std::string current_token = route.substr(b, e - b);
//			tokens_.emplace_back(std::move(current_token));
//
//			if (e == std::string::npos) break;
//
//			b = route.find_first_of('/', e);
//			e = route.find_first_of('/', b + 1);
//		}
//	};
//
//	struct route_metrics
//	{
//		route_metrics() = default;
//		route_metrics(const route_metrics& r) noexcept
//		{
//			request_latency_.store(r.request_latency_);
//			processing_duration_.store(r.processing_duration_);
//			hit_count_.store(r.hit_count_);
//		}
//
//		route_metrics& operator=(const route_metrics& r) noexcept
//		{
//			request_latency_.store(r.request_latency_);
//			processing_duration_.store(r.processing_duration_);
//			hit_count_.store(r.hit_count_);
//		}
//
//		route_metrics(route_metrics&& r) noexcept
//		{
//			request_latency_.store(r.request_latency_);
//			processing_duration_.store(r.processing_duration_);
//			hit_count_.store(r.hit_count_);
//		}
//
//		route_metrics& operator=(route_metrics&& r) noexcept
//		{
//			request_latency_.store(r.request_latency_);
//			processing_duration_.store(r.processing_duration_);
//			hit_count_.store(r.hit_count_);
//		}
//
//		std::atomic<std::chrono::high_resolution_clock::duration> request_latency_{};
//		std::atomic<std::chrono::high_resolution_clock::duration> processing_duration_{};
//
//		std::atomic<std::int64_t> hit_count_{ 0 };
//
//		std::string to_string()
//		{
//			std::stringstream s;
//
//			s << request_latency_.load().count() / 1000000.0 << "ms, " << processing_duration_.load().count() / 1000000.0 << "ms, " << hit_count_ << "x";
//
//			return s.str();
//		};
//	};
//
//	http::method::method_t method_;
//	const R endpoint_;
//	std::vector<std::string> tokens_;
//	route_metrics metrics_;
//
//	std::string get_route() const
//	{
//		std::stringstream route;
//		for (const auto& token : tokens_)
//			route << token;
//
//		return route.str();
//	}
//
//	void update_metrics(std::chrono::high_resolution_clock::duration request_duration, std::chrono::high_resolution_clock::duration new_processing_duration_)
//	{
//		metrics_.request_latency_.store(request_duration);
//		metrics_.processing_duration_.store(new_processing_duration_);
//		metrics_.hit_count_++;
//	}
//
//	route_metrics& metrics() { return metrics_; }
//
//	router_result::router_result_type match(const http::method::method_t& method, const std::string& url, params& params) const noexcept
//	{
//		// route: /route/:param1/subroute/:param2/subroute
//		// url:   /route/parameter
//
//		/*		if (url == route_)
//				{
//					if (method == method_)
//						return router_result::match_found;
//					else
//						return router_result::no_method;
//				}*/
//
//		// std::vector<std::string> tokens;
//
//		// token = /-----
//
//		auto b = url.find_first_of('/');
//		auto e = url.find_first_of('/', b + 1);
//		bool match = false;
//
//		// for (token = 0; ((b != std::string::npos) && (token < tokens_.size())); token++)
//
//		if (b != std::string::npos)
//		{
//			for (const auto& token : tokens_) // token = 0; ((b != std::string::npos) && (token < tokens_.size())); token++)
//			{
//				// std::string current_token = url.substr(b, e - b);
//
//				//			if (tokens_[token].size() > 2 && ((tokens_[token][1] == ':') || tokens_[token][1] == '{'))
//				if (url.compare(b, e - b, token) == 0)
//				{
//				}
//				else if (((token[1] == ':') || token[1] == '{'))
//				{
//					std::string value = url.substr(b + 1, e - b - 1);
//
//					http::request_parser::url_decode(url.substr(b + 1, e - b - 1), value);
//
//					if (token[1] == ':')
//					{
//						params.insert(token.substr(2, token.size() - 2), value);
//					}
//					else
//					{
//						params.insert(token.substr(2, token.size() - 3), value);
//					}
//				}
//				else
//				{
//					match = false;
//					break;
//				}
//
//				b = url.find_first_of('/', e);
//				e = url.find_first_of('/', b + 1);
//
//				if ((b == std::string::npos) && (*tokens_.rbegin() == token))
//				{
//					match = true;
//					break;
//				}
//				else if (b == std::string::npos)
//				{
//					match = false;
//					break;
//				}
//			}
//		}
//
//		if (match && method_ == method)
//			return router_result::match_found;
//		else if (match)
//		{
//			if (params.empty() == false) params.reset();
//
//			return router_result::no_method;
//		}
//		else
//		{
//			if (params.empty() == false) params.reset();
//			return router_result::no_route;
//		}
//	}
//};
//
//template <typename M = middleware_function_t> class middelware
//{
//public:
//	middelware(const std::string& route, M endpoint)
//		: route_(route)
//		, endpoint_(endpoint)
//	{
//		size_t token = 0;
//
//		// token = /-----
//
//		size_t b = route.find_first_of('/');
//		size_t e = route.find_first_of('/', b + 1);
//
//		for (token = 0; b != std::string::npos; token++)
//		{
//			std::string current_token = route.substr(b, e - b);
//			tokens_.emplace_back(std::move(current_token));
//
//			if (e == std::string::npos) break;
//
//			b = route.find_first_of('/', e);
//			e = route.find_first_of('/', b + 1);
//		}
//	};
//
//	std::string route_;
//	M endpoint_;
//	std::vector<std::string> tokens_;
//
//	bool match(const std::string& url_requested, params& params) const
//	{
//		// route: /route/:param1/subroute/:param2/subroute
//		// url:   /route/parameter
//
//		std::string url = url_requested.substr(0, url_requested.find_first_of('?'));
//
//		if (url.find(route_) == 0) // url starts with route
//		{
//			return true;
//		}
//
//		size_t token = 0;
//
//		// token = /-----
//		auto b = url.find_first_of('/');
//		auto e = url.find_first_of('/', b + 1);
//
//		bool match = false;
//
//		for (token = 0; ((b != std::string::npos) && (token < tokens_.size())); token++)
//		{
//			// std::string current_token = url.substr(b, e - b);
//
//			if (tokens_[token].size() > 2 && (tokens_[token][1] == ':' || tokens_[token][1] == '{'))
//			{
//				if (tokens_[token][1] == ':')
//				{
//					params.insert(tokens_[token].substr(2, tokens_[token].size() - 2), url.substr(b + 1, e - b - 1));
//				}
//				else
//				{
//					params.insert(tokens_[token].substr(2, tokens_[token].size() - 3), url.substr(b + 1, e - b - 1));
//				}
//			}
//			else if (tokens_[token] != url.substr(b, e - b))
//			{
//				match = false;
//				break;
//			}
//
//			b = url.find_first_of('/', e);
//			e = url.find_first_of('/', b + 1);
//
//			if ((b == std::string::npos) && (tokens_.size() - 1 == token))
//			{
//				match = true;
//				break;
//			}
//		}
//		return match;
//	}
//};
//
//template <typename R = route_function_t, typename M = middleware_function_t> class router1
//{
//public:
//	router1()
//		: doc_root_("/var/www"){};
//
//	router1(const std::string& doc_root)
//		: doc_root_(doc_root){};
//
//	std::string to_string()
//	{
//		std::stringstream s;
//
//		for (auto& route : route_registry_)
//		{
//			s << R"(")" << route.get_route() << R"(", )" << http::method::to_string(route.method_) << ", " << route.metrics().to_string() << "\n";
//		}
//
//		return s.str();
//	}
//
//	void use(const std::string& path) { static_content_routes.emplace_back(path); }
//
//	void on_http_method(const std::string& route, const std::string& http_method, R api_method) { route_registry_.emplace_back(http_method, route, api_method); }
//
//	void on_busy(std::function<bool()> on_busy_callback) { on_busy_ = on_busy_callback; }
//
//	void on_idle(std::function<bool()> on_idle_callback) { on_idle_ = on_idle_callback; }
//
//	void on_get(std::string&& route, R&& api_method)
//	{
//		route_registry_.emplace_back(http::method::get, route, api_method);
//
//		/*std::cout << "x         :" << sizeof(route_registry_.rbegin()->x) << "\n";
//		std::cout << "endpoint_ :" << sizeof(route_registry_.rbegin()->endpoint_) << "\n";
//		std::cout << "method_   :" << sizeof(http::method::to_string(route_registry_.rbegin()->method_)) << "\n";
//		std::cout << "route_    :" << sizeof(route_registry_.rbegin()->route_) << "\n";
//		std::cout << "total_    :" << sizeof(route_registry_.rbegin()) << "\n";*/
//	}
//
//	void on_post(std::string&& route, R api_method) { route_registry_.emplace_back(http::method::post, route, api_method); }
//
//	void on_head(std::string&& route, R api_method) { route_registry_.emplace_back(http::method::head, route, api_method); }
//
//	void on_put(std::string&& route, R api_method) { route_registry_.emplace_back(http::method::put, route, api_method); }
//
//	void on_delete(std::string&& route, R api_method) { route_registry_.emplace_back(http::method::delete_, route, api_method); }
//
//	void on_patch(std::string&& route, R api_method) { route_registry_.emplace_back(http::method::patch, route, api_method); }
//
//	void on_options(std::string&& route, R api_method) { route_registry_.emplace_back(http::method::options, route, api_method); }
//
//	void use(std::string&& route, middleware_function_t middleware_function) { api_middleware_table.emplace_back(route, middleware_function); };
//
//	bool serve_static_content(session_handler_type& session)
//	{
//		// auto static_path = std::find(std::begin(this->static_content_routes), std::end(this->static_content_routes),
//		// session.request().target());
//		for (auto& static_route : static_content_routes)
//		{
//			std::string url = session.request().url_requested().substr(0, session.request().url_requested().find_first_of('?'));
//
//			if (url.find(static_route) == 0)
//			{
//				auto file_path = doc_root_ + session.request().target();
//				session.request().target(file_path);
//
//				return true;
//			}
//		}
//		return false;
//	}
//
//	bool call_middleware(session_handler_type& session) const
//	{
//		auto result = true;
//		params params_;
//
//		for (auto& middleware : api_middleware_table)
//		{
//			if (middleware.match(session.request().target(), params_))
//			{
//				if ((result = middleware.endpoint_(session, params_)) == false) break;
//			}
//		}
//
//		return result;
//	}
//
//	http::router_result::router_result_type call_route(session_handler_type& session)
//	{
//		auto best_result = http::router_result::router_result_type::no_route;
//
//		if (!route_registry_.empty())
//		{
//			std::string url = session.request().url_requested().substr(0, session.request().url_requested().find_first_of('?'));
//			params params_;
//
//			for (auto& route : route_registry_)
//			{
//				auto result = route.match(session.request().method(), url, params_);
//
//				if (result == router_result::router_result_type::match_found)
//				{
//					auto t0 = std::chrono::steady_clock::now();
//
//					route.endpoint_(session, params_);
//					auto t1 = std::chrono::steady_clock::now();
//
//					route.update_metrics(std::chrono::duration<std::int64_t, std::nano>(t0 - session.t0()), std::chrono::duration<std::int64_t, std::nano>(t1 - t0));
//					return result;
//				}
//				else if (result == router_result::router_result_type::no_method)
//				{
//					best_result = result;
//				}
//			}
//		}
//
//		return best_result;
//	}
//
//	bool call_on_busy()
//	{
//		if (on_busy_)
//			return on_busy_();
//		else
//			return false;
//	}
//
//	bool call_on_idle()
//	{
//		if (on_idle_)
//			return on_idle_();
//		else
//			return true;
//	}
//
//protected:
//	std::function<bool()> on_busy_;
//	std::function<bool()> on_idle_;
//	std::vector<api::route1<route_function_t>> route_registry_;
//	std::string doc_root_;
//	std::vector<std::string> static_content_routes;
//	std::vector<api::middelware<middleware_function_t>> api_middleware_table;
//};
//
//}