#include <array>
#include <chrono>
#include <csignal>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <utility>
using json = nlohmann::json;

#include "http_upstream_node.h"

namespace neolm
{

namespace pm
{

namespace group
{
class member;

using group_members = std::unordered_map<std::string, pm::group::member>;

class member
{
public:
	member(std::string tenant_id, std::string url) : tenant_id_(std::move(tenant_id)), url_(std::move(url)) {}

	const std::string to_string()
	{
		std::stringstream ret;

		ret << tenant_id_ << " : " << url_ << "\n";

		return ret.str();
	}

	std::string tenant() const { return tenant_id_; }

	/*	void spawn(const std::string& command)
		{
			std::cout << "spawn:" << url_ << "\n";
			auto future_ = std::async(std::launch::async, [this]() { auto result =
	   std::system(url_.c_str()); });
		}*/

private:
	std::string tenant_id_;
	std::string url_;
};

} // namespace group
} // namespace pm

template <class M> class product
{
public:
	product(std::string id, std::string description, M&& m)
		: id_(std::move(id)), description_(std::move(description)), model_(m){};

private:
	std::string id_;
	std::string description_;

	M model_;
};

class user
{
public:
	user(std::string name) : name_(std::move(name)){};

	std::string name_;
};

class server
{
public:
	server(std::string id, std::string hostname) : id_(std::move(id)), hostname_(std::move(hostname)){};

	std::string id_;
	std::string hostname_;
};

class named_user_license
{
public:
	named_user_license(size_t max_heavy, size_t max_light) : max_heavy_(max_heavy), max_light_(max_light){};

private:
	size_t max_heavy_;
	size_t max_light_;
};

class named_server_license
{
public:
	named_server_license(size_t max) : max_(max){};

private:
	size_t max_;
};

class concurrent_user_license
{
public:
	concurrent_user_license(size_t max) : max_(max) {}

private:
	size_t max_;
};

template <class S> class license_manager
{
public:
private:
	class api_server : public S, public http::upstream::enable_server_as_upstream
	{
	public:
		api_server(license_manager& license_manager, http::configuration& configuration)
			: S(configuration), http::upstream::enable_server_as_upstream(this), license_manager_(license_manager)
		{
			// Get secific node info, or get list of nodes per tenant-cluster.
			S::router_.on_get("/pm/tenants/{tenant}/upstreams/{node}", [&](http::session_handler& session) {
				const auto& tenant = session.params().get("tenant");
				const auto& node = session.params().get("node");

				if (tenant.empty() && node.empty())
				{
					for (auto& member : license_manager_.group_members_)
						session.response().body() += member.second.to_string();
				}
				else if (node.empty())
				{
					for (auto& member : license_manager_.group_members_)
						if (member.second.tenant() == tenant) session.response().body() += member.second.to_string();
				}
				else
				{
					const auto& member = license_manager_.group_members_.find(tenant + node);

					if (member != license_manager_.group_members_.end())
						session.response().body() += member->second.to_string();
					else
						session.response().status(http::status::not_found);
				}
			});

			// Remove secific node info, or get list of nodes per tenant-cluster.
			S::router_.on_delete("/pm/tenants/{tenant}/upstreams/{node}", [&](http::session_handler& session) {
				const auto& tenant = session.params().get("tenant");
				const auto& node = session.params().get("node");

				if (tenant.empty() && node.empty())
				{
					license_manager_.group_members_.clear();
					session.response().status(http::status::ok);
				}
				else if (node.empty())
				{
					bool found = false;
					for (auto& member : license_manager_.group_members_)
					{
						if (member.second.tenant() == tenant)
						{
							license_manager_.group_members_.erase(member.first);
							found = true;
						}
					}

					if (found)
						session.response().status(http::status::ok);
					else
						session.response().status(http::status::not_found);
				}
				else
				{
					const auto& member = license_manager_.group_members_.find(tenant + node);

					if (member != license_manager_.group_members_.end())
					{
						license_manager_.group_members_.erase(member);
						session.response().status(http::status::ok);
					}
					else
						session.response().status(http::status::not_found);
				}
			});

			// New node, tenant must exist.
			S::router_.on_put("/pm/tenants/{tenant}/upstreams/{node}", [&](http::session_handler& session) {
				const auto& tenant = session.params().get("tenant");
				const auto& node = session.params().get("node");

				if (tenant.empty() || node.empty())
				{
					session.response().status(http::status::bad_request);
				}
				else
				{
					if (license_manager_.group_members_.find(tenant + node) != license_manager_.group_members_.end())
					{
						session.response().status(http::status::conflict);
					}
					else
					{
						license_manager_.group_members_.emplace(tenant + node, pm::group::member{ tenant, node });

						session.response().status(http::status::created);
					}
				}
			});

			S::router_.on_get("/api/rest/fx/*", [this](http::session_handler& session) {
				session.response().body() += "\nLast Request:\n" + http::to_string(session.request());

				session.response().body() += "\nWild Card Param: '" + session.params().get("*") + "'";
				session.response().status(http::status::ok);
			});

			S::router_.on_get("/api/rest/fx/test/urlencodedparam/{1}", [this](http::session_handler& session) {
				// session.response().body() += "\nLast Request:\n" + http::to_string(session.request());

				session.response().body() += "\nRoute Param 1: '" + session.params().get("1") + "'";
				// session.response().body()
				//	+= "\nQuery Param A: '" + session.request().query().get<std::string>("a c", "not set") + "'";

				session.response().status(http::status::ok);
			});

			S::router_.on_get("/api/rest/fx/test/niek/*", [this](http::session_handler& session) {
				session.response().body() += "\nLast Request:\n" + http::to_string(session.request());

				session.response().body() += "\nWild Card Special Case Param: '" + session.params().get("*") + "'";

				session.response().status(http::status::ok);
			});

			S::router_.on_put("/put_test", [this](http::session_handler& session) {
				session.response().status(http::status::created);

				std::clog << http::to_string(session.request());
			});

			S::router_.on_get(
				S::configuration_.template get<std::string>("internal_base", "") + "/status",
				[this](http::session_handler& session) {
					const auto& format = session.request().get("Accept", "application/json");

					if (format.find("application/json") != std::string::npos)
					{
						S::manager().server_information(http::basic::server::configuration_.to_json_string());
						S::manager().router_information(S::router_.to_json_string());
						session.response().body() = S::manager().to_json_string(
							http::basic::server::server_manager::json_status_options::full);
						session.response().type("json");
					}
					else
					{
						S::manager().server_information(http::basic::server::configuration_.to_string());
						S::manager().router_information(S::router_.to_string());
						session.response().body() = S::manager().to_string();
						session.response().type("text");
					}

					session.response().status(http::status::ok);
				});

			S::router_.on_get(
				S::configuration_.template get<std::string>("internal_base", "") + "/status/{section}",
				[this](http::session_handler& session) {
					S::manager().server_information(S::configuration_.to_json_string());
					S::manager().router_information(S::router_.to_json_string());

					auto section_option = http::basic::server::server_manager::json_status_options::full;

					const auto& section = session.params().get("section");

					if (section == "statistics")
					{
						section_option = http::basic::server::server_manager::json_status_options::server_stats;
					}
					else if (section == "configuration")
					{
						section_option = http::basic::server::server_manager::json_status_options::config;
					}
					else if (section == "router")
					{
						section_option = http::basic::server::server_manager::json_status_options::router;
					}
					else if (section == "access_log")
					{
						section_option = http::basic::server::server_manager::json_status_options::accesslog;
					}
					else
					{
						session.response().status(http::status::not_found);
						return;
					}

					session.response().body() = S::manager().to_json_string(section_option);
					session.response().type("json");

					session.response().status(http::status::ok);
				});

			S::router_.on_get("/no_content", [this](http::session_handler& session) {
				session.params().get("sec2");
				session.response().body() = "body text!";
				session.response().status(http::status::no_content);
			});

			S::router_.on_get("/bshell-workers", [this](http::session_handler& session) {
				session.params().get("sec2");
				session.response().body() = "body text!";
				session.response().status(http::status::no_content);
			});

			S::router_.on_get("/slowmo/{sec}", [this](http::session_handler& session) {
				size_t sec = std::atoi(session.params().get("sec", "2").data());
				std::this_thread::sleep_for(std::chrono::seconds(sec));
				session.response().body() = "slomo:";
				session.response().status(http::status::ok);
			});

			S::router_.on_internal_error([this](http::session_handler& session, std::exception&) {
				session.response().body() = "eroor : ";
				// session.response().body() += e.what();
				session.response().status(http::status::internal_server_error);
			});

			S::router_.use_middleware("/status", "type", "varken::knor_pre", "varken::knor_post");

			S::router_.use_middleware(
				"/status",
				[this](http::api::middleware_lambda_context&, http::session_handler& session) {
					session.response().set("name", "value2");
					return http::api::routing::outcome<std::int64_t>{ 0 };
				},
				[this](http::api::middleware_lambda_context&, http::session_handler& session) {
					session.response().set("name", "value2");
					return http::api::routing::outcome<std::int64_t>{ 0 };
				});

			// std::this_thread::sleep_for(std::chrono::seconds{ 60 });
			S::router_.use();
		}

	private:
		friend class license_manager;
		license_manager& license_manager_;
	};

public:
	license_manager(http::configuration configuration, std::string home_dir)
		: configuration_{ std::move(configuration) }, api_server_(*this, configuration_), home_dir_(std::move(home_dir))
	{
	}

	~license_manager()
	{
		if (api_server_.upstream_controller_) api_server_.upstream_controller_->remove();
	}

	license_manager(const license_manager&) = default;
	license_manager(license_manager&&) = default;

	license_manager& operator=(const license_manager&) = default;
	license_manager& operator=(license_manager&&) = default;

	void start_server()
	{
		this->api_server_.start_server();

		if (api_server_.upstream_controller_) api_server_.upstream_controller_->add();
	}

	void run()
	{
		/*struct test
		{
			test(neolm::license_manager<S>::api_server& api_server_,
		std::function<void(http::session_handler&, const http::api::params&)>& test_function)
			{
				int x = 0;

				std::stringstream s;

				for (auto n = 0; n != 10; n++)
					for (auto i = 0; i != 10; i++)
						for (auto k = 0; k != 10; k++)
							for (auto f = 0; f != 100; f++)
							{
								std::stringstream route;

								route << "/v-" << std::to_string(n) << "/service-" <<
		std::to_string(i) <<
		"/subservice-" << std::to_string(k) << "/route/test-"
									  << std::to_string(x++) << "/{test}/aap";

								api_server_.router_.on_get(std::move(route.str()),
		std::move(test_function));
							}
			}
		};

		std::function<void(http::session_handler&, const http::api::params&)> the_test =
		[](http::session_handler& session) { const auto& test = session.params().get("test");

			if (test.empty())
			{
				session.response().status(http::status::bad_request);
			}
			else
			{
				session.response().body() = "test:" + test;
				session.response().status(http::status::ok);
			}
		};

		test t(this->api_server_, the_test);
		*/

		while (api_server_.active() == http::basic::server::state::active)
		{
			api_server_.logger_.info("Alive!\n");
			std::this_thread::sleep_for(std::chrono::seconds(10));
		}
	}

private:
	http::configuration configuration_;
	api_server api_server_;
	std::string home_dir_;

	pm::group::group_members group_members_;
}; // namespace neolm

} // namespace neolm
