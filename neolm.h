#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <signal.h>
#include <unordered_map>
#include <string>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

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
	member(const std::string& tenant_id, const std::string& url)
		: tenant_id_(tenant_id)
		, url_(url)
	{
	}

	const std::string to_string()
	{
		std::stringstream ret;

		ret << tenant_id_ << " : " << url_ << "\n";

		return ret.str();
	}

	std::string tenant() const { return tenant_id_; }

	void spawn(const std::string& command)
	{
		std::cout << "spawn:" << url_ << "\n";
		auto future_ = std::async(std::launch::async, [this]() { auto result = std::system(url_.c_str()); });
	}

private:
	std::string tenant_id_;
	std::string url_;
};

} // namespace group
} // namespace pm

template <class M> class product
{
public:
	product(const std::string& id, const std::string& description, M&& m)
		: id_(id)
		, description_(description)
		, model_(m){};

private:
	std::string id_;
	std::string description_;

	M model_;
};

class user
{
public:
	user(const std::string& name)
		: name_(name){};

	std::string name_;
};

class server
{
public:
	server(const std::string& id, const std::string& hostname)
		: id_(id)
		, hostname_(hostname){};

	std::string id_;
	std::string hostname_;
};

class named_user_license
{
public:
	named_user_license(size_t max_heavy, size_t max_light)
		: max_heavy_(max_heavy)
		, max_light_(max_light){};

private:
	size_t max_heavy_;
	size_t max_light_;
};

class named_server_license
{
public:
	named_server_license(size_t max)
		: max_(max){};

private:
	size_t max_;
};

class concurrent_user_license
{
public:
	concurrent_user_license(size_t max)
		: max_(max)
	{
	}

private:
	size_t max_;
};

template <class S> class license_manager
{
public:
private:
	class api_server : public S //, public http::upstream::enable_server_as_upstream<http::upstream::for_nginx>
	{
	public:
		api_server(license_manager& license_manager, http::configuration& configuration)
			: S(configuration)
			//			, enable_server_as_upstream(configuration, *this)
			, license_manager_(license_manager)
		{
			S::router_.use("/static/");
			S::router_.use("/images/");
			S::router_.use("/styles/");
			S::router_.use("/index.html");
			S::router_.use("/");
			S::router_.use("/files/");

			S::router_.on_busy([this]() {
				bool result = true;

				std::cout << "busy...\n";

				//				upstream_controller().fork();

				return result;
			});

			S::router_.on_idle([this]() {
				bool result = true;

				if (S::manager().idle_duration() >= 3600)
				{
					S::deactivate();
				}
				return result;
			});

			// Get secific node info, or get list of nodes per tenant-cluster.
			S::router_.on_get("/pm/tenants/:tenant/upstreams/:node", [this](http::session_handler& session, const http::api::params& params) {
				const auto& tenant = params.get("tenant");
				const auto& node = params.get("node");

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
						session.response().result(http::status::not_found);
				}
			});

			// Remove secific node info, or get list of nodes per tenant-cluster.
			S::router_.on_delete("/pm/tenants/:tenant/upstreams/:node", [this](http::session_handler& session, const http::api::params& params) {
				const auto& tenant = params.get("tenant");
				const auto& node = params.get("node");

				if (tenant.empty() && node.empty())
				{
					license_manager_.group_members_.clear();
					session.response().result(http::status::ok);
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
						session.response().result(http::status::ok);
					else
						session.response().result(http::status::not_found);
				}
				else
				{
					const auto& member = license_manager_.group_members_.find(tenant + node);

					if (member != license_manager_.group_members_.end())
					{
						license_manager_.group_members_.erase(member);
						session.response().result(http::status::ok);
					}
					else
						session.response().result(http::status::not_found);
				}
			});

			// New node, tenant must exist.
			S::router_.on_put("/pm/tenants/:tenant/upstreams/:node", [this](http::session_handler& session, const http::api::params& params) {
				const auto& tenant = params.get("tenant");
				const auto& node = params.get("node");

				if (tenant.empty() || node.empty())
				{
					session.response().result(http::status::bad_request);
				}
				else
				{
					if (license_manager_.group_members_.find(tenant + node) != license_manager_.group_members_.end())
					{
						session.response().result(http::status::conflict);
					}
					else
					{
						const auto& key = license_manager_.group_members_.emplace(tenant + node, pm::group::member{ tenant, node });

						session.response().result(http::status::created);
					}
				}
			});

			S::router_.on_get("/status", [this](http::session_handler& session, const http::api::params& params) {
				S::manager().server_information(S::configuration_.to_string());
				S::manager().router_information(S::router_.to_string());

				session.response().body().reserve(8192 * 4);
				session.response().body() = S::manager().to_string();

				session.response().body() += "\nLast Request:\n" + http::to_string(session.request());
				session.response().type("text");
			});
		}

	private:
		friend class license_manager;
		license_manager& license_manager_;
	};

public:
	license_manager(const http::configuration& configuration, const std::string& home_dir)
		: configuration_{ configuration }
		, api_server_(*this, configuration_)
		, home_dir_(home_dir)
	{
	}

	~license_manager() = default;

	license_manager(const license_manager&) = default;
	license_manager(license_manager&&) = default;

	license_manager& operator=(const license_manager&) = default;
	license_manager& operator=(license_manager&&) = default;

	void start_server()
	{
		this->api_server_.start_server();
		/*		if (this->api_server_.upstream_controller().add(configuration_.get("upstream-node-nginx-endpoint-myip") + ":" + configuration_.get("http_listen_port")) ==
		   http::upstream::sucess) std::cout << "server listening on port : " + configuration_.get("http_listen_port") + " and added to upstream\n"; else */
		std::cout << "server listening on port : " + configuration_.get("http_listen_port") + "\n";
	}

	void run()
	{
		for (auto i = 0; i != 2000; i++)
		{

			api_server_.router_.on_get(
				std::move("/testtesttest/testtesttest/testtesttest/test-" + std::to_string(i) + "/:test"), [](http::session_handler& session, const http::api::params& params) {
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

		do
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			std::cout << "neolm::run\n";

		} while (api_server_.active_ == true);
	}

private:
	http::configuration configuration_;
	api_server api_server_;
	std::string home_dir_;

	pm::group::group_members group_members_;
};

} // namespace neolm
