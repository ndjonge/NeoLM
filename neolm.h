#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>

#include "json.h"

#include <signal.h>

using namespace std::literals;

namespace neolm
{
class instance;
template <class M> class product;

class user;
class server;
class named_user_license;
class concurrent_user_license;
class named_server_license;

using instances = std::unordered_map<std::string, neolm::instance>;
using concurrent_user_licenses = std::unordered_map<std::string, neolm::product<neolm::concurrent_user_license>>;
using named_user_licenses = std::unordered_map<std::string, neolm::product<neolm::named_user_license>>;
using named_server_licenses = std::unordered_map<std::string, neolm::product<neolm::named_server_license>>;

using users = std::unordered_map<std::string, neolm::user>;
using servers = std::unordered_map<std::string, neolm::server>;

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

	friend json::value to_json(const product<M>& m)
	{
		json::object ret;

		ret.emplace(std::string("id"), json::string(m.id_));
		ret.emplace(std::string("description"), json::string(m.description_));
		// product_json.emplace(std::string("id"), json::string(product.second.model_));

		return ret;
	}

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

class instance
{
public:
	instance(json::value& instance_license, json::value& instance_allocation)
	{
		id_ = json::get<std::string>(instance_license["id"]);
		name_ = json::get<std::string>(instance_license["name"]);
		license_key_ = json::get<std::string>(instance_license["key"]);
		license_hash_ = json::get<std::string>(instance_license["bind_to"]);

		auto named_user_license_definitions = instance_license["named-user"].as_array();
		auto named_server_license_definitions = instance_license["named-server"].as_array();
		auto concurrent_user_license_definitions = instance_license["concurrent-user"].as_array();

		for (auto& named_user_license_definition : named_user_license_definitions)
		{
			named_user_licenses_.emplace(
				json::get<std::string>(named_user_license_definition["id"]), product<named_user_license>(
																				 json::get<std::string>(named_user_license_definition["id"]), json::get<std::string>(named_user_license_definition["description"]),
																				 named_user_license(json::get<std::size_t>(named_user_license_definition["max_heavy"]), json::get<std::size_t>(named_user_license_definition["max_light"]))));
		}

		for (auto& named_server_license_definition : named_server_license_definitions)
		{
			named_server_licenses_.emplace(
				json::get<std::string>(named_server_license_definition["id"]),

				product<named_server_license>(
					json::get<std::string>(named_server_license_definition["id"]), json::get<std::string>(named_server_license_definition["description"]),
					named_server_license(json::get<std::size_t>(named_server_license_definition["max"]))));
		}

		for (auto& concurrent_user_license_definition : concurrent_user_license_definitions)
		{
			concurrent_user_licenses_.emplace(
				json::get<std::string>(concurrent_user_license_definition["id"]),

				product<concurrent_user_license>(
					json::get<std::string>(concurrent_user_license_definition["id"]), json::get<std::string>(concurrent_user_license_definition["description"]),
					concurrent_user_license(json::get<std::size_t>(concurrent_user_license_definition["max"]))));
		}

		auto users = instance_allocation["users"].as_array();
		auto servers = instance_allocation["servers"].as_array();

		for (auto& user : users)
		{
			users_.emplace(json::get<std::string>(user["name"]), json::get<std::string>(user["name"]));
		}

		for (auto& server : servers)
		{
			servers_.emplace(json::get<std::string>(server["name"]), neolm::server(json::get<std::string>(server["name"]), json::get<std::string>(server["name"])));
		}
	}

	std::string id_;
	std::string name_;
	std::string license_key_;
	std::string license_hash_;

	named_user_licenses named_user_licenses_;
	named_server_licenses named_server_licenses_;
	concurrent_user_licenses concurrent_user_licenses_;

	users users_;
	servers servers_;

	std::int32_t sequence_ = 0;

	class license_aquired
	{
	public:
		license_aquired(json::object& request_license)
			: product_id_(json::get<std::string>(request_license["product_id"]))
			, parameter_(json::get<std::string>(request_license["parameter"]))
			, tag_(json::get<std::string>(request_license["tag"]))
			, hostname_(json::get<std::string>(request_license["hostname"]))
			, sequence_id_(1)
			, last_confirm_(0)
		{
		}

		const std::string as_id() const
		{
			std::stringstream s;

			s << product_id_ << "/" << parameter_ << "/" << hostname_ << "/" << sequence_id_;

			auto h = std::hash<std::string>{}(s.str());

			return std::to_string(h);
		}

		friend class instance;
		friend json::value to_json(const instance::license_aquired& license_aquired);

	private:
		std::string product_id_;
		std::string parameter_;
		std::string tag_;
		std::string hostname_;
		std::int32_t sequence_id_;
		std::int64_t last_confirm_;
	};

	json::object about_license(std::string license_id)
	{
		json::object ret;

		try
		{
			auto& i = licenses_aquired_.at(license_id);

			ret.emplace("id", license_id);
			ret.emplace("hostname", i.hostname_);
			ret.emplace("last-confirm", i.last_confirm_);
			ret.emplace("parameter", i.parameter_);
			ret.emplace("sequence", i.sequence_id_);
		}
		catch (const std::out_of_range&)
		{
		}

		return ret;
	}

	json::object request_license(json::object& request_license)
	{
		json::object ret;

		license_aquired license_aquired(request_license);

		ret.emplace("license_id:", license_aquired.as_id());

		auto i = licenses_aquired_.emplace(std::make_pair(license_aquired.as_id(), std::move(license_aquired)));

		return ret;
	}

	json::object confirm_license(std::string license_id)
	{
		json::object ret;

		auto& i = licenses_aquired_.at(std::string(license_id));

		i.last_confirm_ += 600;

		ret.emplace("id", license_id);
		ret.emplace("last-confirm", i.last_confirm_);

		return ret;
	}

	json::object release_license(std::string license_id)
	{
		json::object ret;

		auto i = licenses_aquired_.erase(license_id);

		if (i > 0)
		{
			ret.emplace("id", license_id);
			ret.emplace("in-use-duration", "0");
		}

		return ret;
	}

	std::unordered_map<std::string, license_aquired> licenses_aquired_;
};

json::value to_json(const instance::license_aquired& license_aquired)
{
	json::object ret;

	ret.emplace("license_id", license_aquired.as_id());

	return ret;
}

json::value to_json(const named_user_licenses& name_user_licenses)
{
	json::array ret;

	for (const auto& name_user_license : name_user_licenses)
	{
		ret.emplace_back(to_json(name_user_license.second));
	}

	return ret;
}

json::value to_json(const named_server_licenses& name_server_licenses)
{
	json::array ret;

	for (const auto& name_server_license : name_server_licenses)
	{
		ret.emplace_back(to_json(name_server_license.second));
	}

	return ret;
}

json::value to_json(const concurrent_user_licenses& concurrent_user_licenses)
{
	json::array ret;

	for (const auto& concurrent_user_license : concurrent_user_licenses)
	{
		ret.emplace_back(to_json(concurrent_user_license.second));
	}

	return ret;
}

json::value to_json(const instance& instance)
{
	json::object ret;

	ret.emplace(std::string("id"), json::string(instance.id_));
	ret.emplace(std::string("name"), json::string(instance.name_));
	ret.emplace(std::string("key"), json::string(instance.license_key_));
	ret.emplace(std::string("bind-to"), json::string(instance.license_hash_));

	json::array products_json;

	for (auto&& product : instance.named_user_licenses_)
	{
		products_json.emplace_back(to_json(product.second).as_object());
	}

	ret.emplace(std::string("named-user-licenses"), products_json);

	for (auto&& product : instance.named_server_licenses_)
	{
		products_json.emplace_back(to_json(product.second).as_object());
	}

	ret.emplace(std::string("named-server-licenses"), products_json);

	for (auto&& product : instance.concurrent_user_licenses_)
	{
		products_json.emplace_back(to_json(product.second).as_object());
	}

	ret.emplace(std::string("concurrent-user-licenses"), products_json);

	return ret;
}

json::value to_json(const instances& instances)
{
	json::array ret;

	for (const auto& instance : instances)
	{
		ret.emplace_back(to_json(instance.second).as_object());
	}

	return ret;
}

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
					auto& member = license_manager_.group_members_.find(tenant + node);

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
					auto& member = license_manager_.group_members_.find(tenant + node);

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
						auto& key = license_manager_.group_members_.emplace(tenant + node, pm::group::member{ tenant, node });

						session.response().result(http::status::created);
					}
				}
			});

			// License instance configuration routes..
			S::router_.on_get("/licenses/configuration", [this](http::session_handler& session, const http::api::params& params) {
				std::string instance_id = session.request().get("instance");

				if (instance_id.empty())
				{
					instance_id = "main";
				}

				auto instance = license_manager_.get_instances().at(instance_id);

				json::object return_json;

				return_json.emplace(std::string("id"), json::string(instance.id_));
				return_json.emplace(std::string("name"), json::string(instance.name_));
				return_json.emplace(std::string("key"), json::string(instance.license_key_));
				return_json.emplace(std::string("bind-to"), json::string(instance.license_hash_));

				session.response().body() = json::serializer::serialize(return_json).str();
				session.response().type("json");
			});

			S::router_.on_get("/licenses/:product-id/acquisition/:license-id", [this](http::session_handler& session, const http::api::params& params) {
				// refresh --> put
				std::string instance_id = session.request().get("instance");
				const std::string& license_id = params.get("license-id");

				if (instance_id.empty())
				{
					instance_id = "main";
				}

				const std::string& product_id = params.get("product-id");

				auto instance = license_manager_.get_instances().at(instance_id);

				auto return_json = instance.about_license(license_id);

				session.response().body() = json::serializer::serialize(return_json).str();
				session.response().type("json");
			});

			S::router_.on_put("/licenses/:product-id/acquisition", [this](http::session_handler& session, const http::api::params& params) {
				// 0 - Validate
				std::string instance_id = session.request().get("instance");
				const std::string& product_id = params.get("product-id");

				if (instance_id.empty())
				{
					instance_id = "main";
				}

				auto instance = license_manager_.get_instances().at(instance_id);

				// 1 - Process
				auto request_json = json::parser::parse(session.request().body());

				// 2 - Return result

				request_json.get_object().emplace("product_id", product_id);
				request_json.get_object().emplace("hostname", session.request().get("Remote_Addr"));

				auto return_json = instance.request_license(request_json.get_object());

				session.response().body() = json::serializer::serialize(return_json).str();
				session.response().type("json");
			});

			S::router_.on_post("/licenses/:product-id/acquisition/:license-id", [this](http::session_handler& session, const http::api::params& params) {
				std::string instance_id = session.request().get("instance");
				const std::string& license_id = params.get("license-id");

				if (instance_id.empty())
				{
					instance_id = "main";
				}

				const std::string& product_id = params.get("product-id");

				auto instance = license_manager_.get_instances().at(instance_id);

				const auto& return_json = instance.confirm_license(license_id);

				session.response().body() = json::serializer::serialize(return_json).str();
				session.response().type("json");
			});

			S::router_.on_delete("/licenses/:product-id/acquisition/:license-id", [this](http::session_handler& session, const http::api::params& params) {
				std::string instance_id = session.request().get("instance");
				const std::string& license_id = params.get("license-id");

				if (instance_id.empty())
				{
					instance_id = "main";
				}

				const std::string& product_id = params.get("product-id");

				auto instance = license_manager_.get_instances().at(instance_id);

				auto return_json = instance.release_license(license_id);

				session.response().body() = json::serializer::serialize(return_json).str();
				session.response().type("json");
			});

			S::router_.on_get("/status", [this](http::session_handler& session, const http::api::params& params) {
				S::manager().server_information(S::configuration_.to_string());
				S::manager().router_information(S::router_.to_string());
				session.response().body() = S::manager().to_string();
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
		json::value instance_definitions = json::parser::parse(std::ifstream(home_dir_ + "instances.json"));

		for (auto& instance_definition : instance_definitions.get_array())
		{
			std::string instance_id = instance_definition["instance"].as_string();
			std::string license_file = home_dir_ + instance_id + "/license.json";
			std::string allocation_file = home_dir_ + instance_id + "/allocation.json";

			json::value instance_license = json::parser::parse(std::ifstream(license_file));
			json::value instance_allocation = json::parser::parse(std::ifstream(allocation_file));

			this->instances_.emplace(instance_id, instance(instance_license, instance_allocation));
		}
	}

	~license_manager() {}

	license_manager(const license_manager&) = default;
	license_manager(license_manager&&) = default;

	license_manager& operator=(const license_manager&) = default;
	license_manager& operator=(license_manager&&) = default;

	void start_server()
	{
		this->api_server_.start_server();
		/*		if (this->api_server_.upstream_controller().add(configuration_.get("upstream-node-nginx-endpoint-myip") + ":" + configuration_.get("http_listen_port")) == http::upstream::sucess)
					std::cout << "server listening on port : " + configuration_.get("http_listen_port") + " and added to upstream\n";
				else */
		std::cout << "server listening on port : " + configuration_.get("http_listen_port") + "\n";
	}

	void run()
	{
		do
		{
			// load_test();
			std::this_thread::sleep_for(1s);
			std::cout << "neolm::run\n";

		} while (api_server_.active_ == true);
	}

	instances& get_instances() { return instances_; }

private:
	http::configuration configuration_;
	api_server api_server_;
	std::string home_dir_;
	instances instances_;

	pm::group::group_members group_members_;
};

} // namespace neolm
