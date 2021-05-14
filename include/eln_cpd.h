#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>

// wireshark:
// portrange 8000-8032 or port 4000

#define CURL_STATICLIB

#ifdef USE_VCPKG_INCLUDES
#include "nlohmann/json.hpp"
#else
#include "nlohmann_json.hpp"
#endif

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#ifdef LOCAL_TESTING
#define get_version_ex(PORT_SET, NULL) "1.0"
#define PORT_SET "9.4x"
#endif


#include "http_async.h"
#include "http_basic.h"
#include "http_network.h"
#include "prog_args.h"
#include "eln_cpm_worker.h"
using json = nlohmann::json;

namespace tests
{
using configuration = http::configuration;

class test_base
{

private:
	std::string base_url_;
	tests::configuration configuration_;

public:
	test_base(const std::string& base_url, const tests::configuration& configuration)
		: base_url_(base_url), configuration_(configuration)
	{
	}

	inline bool add_workspace(std::string workspace_id, std::string tenant_id)
	{
		json workspace_def{ { "workspace",
							  { { "id", workspace_id },
								{ "routes",
								  { { "paths", { "/api", "/internal" } },
									{ "methods", { "get", "head", "post" } },
									{ "headers", { { "X-Infor-TenantId", { tenant_id } } } } } } } } };

		std::string error;

		auto response = http::client::request<http::method::post>(
			base_url_ + "/internal/platform/manager/workspaces", error, {}, workspace_def["workspace"].dump());

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool add_workgroup(
		std::string workspace_id,
		std::string workgroup_name,
		std::string worker_bse,
		std::string worker_bse_bin,
		std::string worker_cmd,
		std::string worker_options,
		int required,
		int start_at_once)
	{
		if (worker_cmd.find("eln_cpm") == 0)
		{
			if (worker_options.empty())
				worker_options = "-selftests_worker ";
			else
				worker_options += " -selftests_worker ";
		}
		json workgroup_def{ { "name", workgroup_name },
							{ "type", "bshells" },
#ifdef _WIN32
							{ "parameters",
							  { { "program", worker_cmd + ".exe" },
								{ "cli_options", worker_options },
								{ "bse", worker_bse },
								{ "bse_bin", worker_bse_bin } } },
#else
							{ "parameters", { { "program", worker_cmd }, { "cli_options", worker_options } } },
#endif
							{ "limits",
							  { { "workers_min", required },
								{ "workers_max", 16 },
								{ "workers_required", required },
								{ "workers_runtime_max", 1 },
								{ "workers_start_at_once_max", start_at_once } } } };
		// std::cout << workgroup_def.dump(4, ' ') << "\n";

		std::string error;

		auto response = http::client::request<http::method::post>(
			base_url_ + "/internal/platform/director/workspaces/" + workspace_id + "/workgroups",
			error,
			{},
			workgroup_def.dump());

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool increase_workgroup_limits(std::string workspace_id, std::string workgroup_name, int required)
	{
		json limits_def{ { "limits", { { "workers_required", required } } } };

		// std::cout << workgroup_def.dump(4, ' ') << "\n";

		std::string error;

		auto response = http::client::request<http::method::put>(
			base_url_ + "/internal/platform/director/workspaces/" + workspace_id + "/workgroups/" + workgroup_name
				+ "/limits/workers_required",
			error,
			{},
			limits_def.dump());

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool remove_workgroup(std::string workspace_id, std::string workgroup_name)
	{
		std::string error;

		auto response = http::client::request<http::method::delete_>(
			base_url_ + "/internal/platform/manager/workspaces/" + workspace_id + "/workgroups/" + workgroup_name,
			error,
			{});

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool remove_workspace(std::string workspace_id)
	{
		std::string error;

		auto response = http::client::request<http::method::delete_>(
			base_url_ + "/internal/platform/manager/workspaces/" + workspace_id, error, {});

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool run()
	{
		const int workspace_count = configuration_.get<int>("workspaces", 1);
		const int workgroup_count = configuration_.get<int>("workgroups", 1);
		const int run_count = configuration_.get<int>("runs", -1);
		const int worker_count = configuration_.get<int>("workers_min", 0);
		const int worker_start_at_once_count = configuration_.get<int>("workers_start_at_once", 1);
		const bool clean_up = configuration_.get<bool>("cleanup", true);
		const int stay_alive_time = configuration_.get<int>("stay_alive_time", 6000);

		const std::string& worker_cmd = configuration_.get<std::string>("worker_cmd", "eln_cpm");
		const std::string& worker_options = configuration_.get<std::string>("worker_options", "");

		const std::string& worker_bse = configuration_.get<std::string>("bse", "");
		const std::string& worker_bse_bin = configuration_.get<std::string>("bse_bin", "");

		for (int n = 0; n != run_count; n++)
		{
			for (int i = 0; i < workspace_count; i++)
				add_workspace("workspace_" + std::to_string(100 + i), "tenant" + std::to_string(100 + i) + "_tst");

			for (int j = 0; j < workspace_count; j++)
				for (int i = 0; i < workgroup_count; i++)
					add_workgroup(
						"workspace_" + std::to_string(100 + j),
						"workgroup_" + std::to_string(i),
						worker_bse,
						worker_bse_bin,
						worker_cmd,
						worker_options,
						worker_count,
						worker_start_at_once_count);

			for (int j = 0; j < workspace_count; j++)
				for (int i = 0; i < workgroup_count; i++)
					increase_workgroup_limits(
						"workspace_" + std::to_string(100 + j), "workgroup_" + std::to_string(i), worker_count);

			if (n + 1 == run_count && clean_up == false) break;

			std::this_thread::sleep_for(std::chrono::seconds(stay_alive_time));

			for (int j = 0; j < workspace_count; j++)
				for (int i = 0; i < workgroup_count; i++)
					remove_workgroup("workspace_" + std::to_string(100 + j), "workgroup_" + std::to_string(i));

			for (int i = 0; i < workspace_count; i++)
				remove_workspace("workspace_" + std::to_string(100 + i));

			std::this_thread::sleep_for(std::chrono::seconds(10));
		}

		return true;
	}
};

} // namespace tests

namespace cloud
{

namespace platform
{

class workspace;
class workgroup;
class workspaces;

namespace output_formating
{

enum class options
{
	complete,
	essential
};

}

class workspace
{
public:
	using key_type = std::string;
	using value_type = std::unique_ptr<workgroup>;
	using container_type = std::map<key_type, value_type>;
	using iterator = container_type::iterator;
	using const_iterator = container_type::const_iterator;
	using route_methods_type = std::vector<http::method::method_t>;
	using route_path_type = std::vector<std::string>;
	using route_headers_type = std::vector<http::field<std::string>>;
	using mutex_type = std14::shared_mutex;

	enum class state
	{
		down,
		up,
		drain
	};

private:
	std::string server_endpoint_;
	std::string workspace_id_{};
	std::string tenant_id_{};
	std::string description_{};

	route_methods_type methods_;
	route_path_type paths_;
	route_headers_type headers_;
	mutable mutex_type workers_mutex;
	container_type workgroups_;

	enum state state_;

public:
	const route_path_type& paths() const { return paths_; }
	const route_headers_type& headers() const { return headers_; }
	const route_methods_type& methods() const { return methods_; }

	mutable mutex_type workgroups_mutex_;

	mutex_type& workgroups_mutex() const { return workgroups_mutex_; }

	state state() const { return state_; }
	void state(enum cloud::platform::workspace::state s) { state_ = s; }

public:
	workspace(const std::string workspace_id, const json& json_workspace)
		: workspace_id_(workspace_id), state_(state::up)
	{
		from_json(json_workspace);
	}

	workspace(const workspace&) = delete;

	const std::string& get_workspace_id(void) const { return workspace_id_; };
	void set_workspace_id(const std::string& workspace_id) { workspace_id_ = workspace_id; };

	const std::string& get_description(void) const { return description_; };
	const std::string& get_tenant_id(void) const { return tenant_id_; };

public:
	void to_json(json& workspace, output_formating::options options = output_formating::options::complete) const
	{
		workspace["id"] = workspace_id_;
		workspace["description"] = description_;

		if (paths_.empty() == false)
		{
			for (const auto& paths : paths_)
				workspace["routes"]["paths"].emplace_back(paths);
		}

		if (methods_.empty() == false)
		{
			for (const auto& method : methods_)
				workspace["routes"]["methods"].emplace_back(http::method::to_string(method));
		}

		if (headers_.empty() == false)
		{
			for (auto& header : headers_)
				workspace["routes"]["headers"][header.name].emplace_back(header.value);
		}

		json workgroups_json;

		for (auto& named_worker : workgroups_)
		{
			json named_worker_json = json::object();

			named_worker.second->to_json(named_worker_json, options);

			workgroups_json.emplace_back(named_worker_json);
		}
		workspace["workgroups"] = workgroups_json;
	}

private:
	std::unique_ptr<workgroup> create_workgroup_from_json(const std::string& type, const json& workgroup_json)
	{
		if (type == "bshells")
			return std::unique_ptr<workgroup>{ new bshell_workgroup{ workspace_id_, workgroup_json } };
		if (type == "ashells")
			return std::unique_ptr<workgroup>{ new bshell_workgroup{ workspace_id_, workgroup_json } };
		if (type == "python-scripts")
			return std::unique_ptr<workgroup>{ new python_workgroup{ workspace_id_, workgroup_json } };
		else
			return nullptr;
	}

public:
	iterator erase_workgroup(iterator i) { return workgroups_.erase(i); }

	iterator end() { return workgroups_.end(); };
	iterator begin() { return workgroups_.begin(); }
	const_iterator cend() const { return workgroups_.cend(); };
	const_iterator cbegin() const { return workgroups_.cbegin(); }

	bool has_workgroups_available() const { return workgroups_.empty() == false; }

	bool drain_all_workgroups()
	{
		bool result = false;

		for (auto& workgroup : workgroups_)
		{
			if (workgroup.second->state() == workgroup::state::up) workgroup.second->state(workgroup::state::drain);
			result = true;
		}

		return result;
	}

	void proxy_pass(http::session_handler& session) const
	{
		std14::shared_lock<workspace::mutex_type> l{ workgroups_mutex_ };

		for (const auto& workgroup : workgroups_)
		{
			bool methods_match = false;
			bool header_match = false;
			bool path_match = false;

			if (workgroup.second->methods().empty() == false)
			{
				for (const auto& method : methods_)
				{
					if (session.request().method() == method)
					{
						methods_match = true;
						break;
					}
				}
			}
			else
			{
				methods_match = true;
			}

			if (methods_match && workgroup.second->headers().empty() == false)
			{
				for (const auto& header : workgroup.second->headers())
				{
					//bool found = false;
					//if (session.request().get<std::string>(header.name, found, "") == header.value && found == true)

					if (session.request().get<std::string>(header.name, "") == header.value)
					{
						header_match = true;
						break;
					}
				}
			}
			else
			{
				header_match = methods_match;
			}

			if (header_match && workgroup.second->paths().empty() == false)
			{
				for (const auto& workspace_path : paths_)
				{
					for (const auto& workgroup_path : workgroup.second->paths())
					{
						if (session.request().url_requested().find(workspace_path + workgroup_path) == 0)
						{
							path_match = true;
							break;
						}
					}
				}
			}
			else
			{
				path_match = header_match && methods_match;
			}

			if (methods_match && header_match && path_match)
			{
				if (workgroup.second->has_workers_available())
				{
					if (session.protocol() == http::protocol::https)
					{
						session.request().set("X-Forwarded-Proto", "https");
					}

					session.request().set_attribute<http::async::upstreams*>(
						"proxy_pass", &workgroup.second->upstreams_);
				}
				else
				{
					if (workgroup.second->workgroups_limits().workers_max() > 0)
					{
						std::int16_t queue_retry_timeout
							= workgroup.second->workgroups_limits().workers_queue_retry_timeout();
						std::int16_t scale_out_factor = workgroup.second->workgroups_limits().worker_scale_out_factor();

						if (workgroup.second->workgroups_limits().workers_pending() == 0)
						{
							workgroup.second->workgroups_limits().workers_required_upd(scale_out_factor);
						}

						session.request().set_attribute<std::int16_t>("queued", queue_retry_timeout);
					}
					else
					{
						session.response().status(http::status::service_unavailable);
					}
				}
				break;
			}
		}
	}

	bool add_workgroup(const std::string& name, const std::string& type, json& workgroup_json)
	{
		auto new_workgroup = create_workgroup_from_json(type, workgroup_json);

		if (new_workgroup)
		{
			auto result
				= workgroups_.insert(std::pair<key_type, value_type>(key_type{ name }, std::move(new_workgroup)));

			return result.second;
		}

		return false;
	}

	bool drain_workgroup(const std::string& workgroup_name)
	{
		bool result = false;

		auto workgroup = workgroups_.find(key_type{ workgroup_name });

		if (workgroup != workgroups_.end()) workgroup->second->state(workgroup::state::drain);

		return result;
	}

	void from_json(const json& j)
	{
		description_ = j.value("description", "");

		if (j.contains("routes"))
		{
			if (j["routes"].contains("headers"))
			{
				for (auto& header : j["routes"]["headers"].items())
				{
					auto key = header.key();
					for (auto& header_value : header.value())
						headers_.emplace_back(header.key(), header_value);
				}
			}

			if (j["routes"].contains("paths"))
			{
				for (auto& path : j["routes"]["paths"].items())
					paths_.emplace_back(path.value());
			}

			if (j["routes"].contains("methods"))
			{
				for (auto& method : j["routes"]["methods"].items())
					methods_.emplace_back(http::method::to_method(util::to_upper(method.value())));
			}
		}

		if (j.find("workgroups") != j.end())
		{
			json json_workgroups = j.at("workgroups");

			for (auto workgroup = json_workgroups.cbegin(); workgroup != json_workgroups.cend(); workgroup++)
			{
				if (workgroup.value().size())
				{
					auto new_workgroup = create_workgroup_from_json(workgroup.value()["type"], *workgroup);

					if (new_workgroup)
					{
						workgroups_[key_type{ workgroup.value()["name"] }] = std::move(new_workgroup);
					}
				}
			}
		}
	}
};

inline void to_json(json& j, const workspace& w) { w.to_json(j); }

class workspaces
{
public:
	using value_type = std::unique_ptr<workspace>;
	using container_type = std::map<const std::string, value_type>;

	using iterator = container_type::iterator;
	using const_iterator = container_type::const_iterator;
	using mutex_type = std14::shared_mutex;

private:
	container_type workspaces_;

	std::string port;
	std::string base_path;
	std::string manager_workspace;

	std::atomic<bool> is_changed_{ true };
	mutable std14::shared_mutex workspaces_mutex_;

public:
	iterator end() { return workspaces_.end(); }
	iterator begin() { return workspaces_.begin(); }
	const_iterator cend() const { return workspaces_.cend(); }
	const_iterator cbegin() const { return workspaces_.cbegin(); }

	const std::atomic<bool>& is_changed() const { return is_changed_; }
	void is_changed(bool value) { is_changed_ = value; }

	mutex_type& workspaces_mutex() { return workspaces_mutex_; }
	const mutex_type& workspaces_mutex() const { return workspaces_mutex_; }

	iterator erase_workspace(iterator i) { return workspaces_.erase(i); }

	void cleanup_workspaces(lgr::logger& logger)
	{
		std::unique_lock<mutex_type> l1{ workspaces_mutex_ };

		for (auto workspace = workspaces_.begin(); workspace != workspaces_.end();)
		{
			auto workspace_state = workspace->second->state();

			if (workspace->second->has_workgroups_available())
			{
				std::unique_lock<mutex_type> l2{ workspace->second->workgroups_mutex() };
				for (auto workgroup = workspace->second->begin(); workgroup != workspace->second->end();)
				{
					auto workgroup_state = workgroup->second->state();

					if (workgroup_state == workgroup::state::drain)
					{
						if ((workgroup->second->workgroups_limits().workers_actual() > 0)
							|| (workgroup->second->workgroups_limits().workers_pending() > 0))
						{
							workgroup->second->drain_all_workers();
						}
						else
						{
							workgroup->second->state(workgroup::state::down);
							workgroup_state = workgroup->second->state();
						}
					}

					if (workgroup_state == workgroup::state::down)
					{
						logger.api("workspace: {s}, erase worker: {s}\n", workspace->first, workgroup->first);
						workgroup = workspace->second->erase_workgroup(workgroup);
					}
					else
						workgroup++;
				}
			}

			if (workspace_state == workspace::state::drain)
			{
				if (workspace->second->has_workgroups_available())
				{
					workspace->second->drain_all_workgroups();
				}
				else
				{
					workspace->second->state(workspace::state::down);
					workspace_state = workspace->second->state();
				}
			}

			if (workspace_state == workspace::state::down)
			{
				logger.api("erase workspace: {s}\n", workspace->first);
				workspace = erase_workspace(workspace);
			}
			else
				workspace++;
		}
		is_changed_ = true;
	}

	void direct_workspaces(asio::io_context& io_context, const http::configuration& configuration, lgr::logger& logger)
	{
		auto t0 = std::chrono::steady_clock::now();
		bool needs_cleanup = false;

		{
			std14::shared_lock<mutex_type> l1{ workspaces_mutex_ };
			auto is_changed_new = false;
			for (auto workspace = workspaces_.begin(); workspace != workspaces_.end(); ++workspace)
			{
				if (workspace->second->state() != workspace::state::up) needs_cleanup = true;

				if (workspace->second->has_workgroups_available())
				{
					std14::shared_lock<mutex_type> l2{ workspace->second->workgroups_mutex() };
					for (auto workgroup = workspace->second->begin(); workgroup != workspace->second->end();
						 ++workgroup)
					{
						if (workgroup->second->state() != workgroup::state::up) needs_cleanup = true;
						
						is_changed_new |= workgroup->second->direct_workers(io_context, configuration, logger, is_changed_);
					}
				}
			}
			is_changed(is_changed_new);
		}


		auto t1 = std::chrono::steady_clock::now();
		auto elapsed = t1 - t0;

		if (needs_cleanup) cleanup_workspaces(logger);

		logger.info("{u} workspaces took {d}msec\n", workspaces_.size(), elapsed.count() / 1000000);
	}

public:
	bool add_workspace(const std::string id, const json::value_type& j)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		bool result = false;
		auto i = workspaces_.find(id);

		if (i == workspaces_.end())
		{
			auto new_workspace = workspaces_.insert(container_type::value_type{ id, new workspace{ id, j } });

			result = new_workspace.second; // add_workspace returns true when an inserted happend.
		}

		return result;
	}

	bool drain_workspace(const std::string id)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		auto i = workspaces_.find(id);

		if (i == workspaces_.end())
		{
			return false;
		}
		else
		{
			workspaces_.erase(i);
			return true;
		}
	}

	void proxy_pass(http::session_handler& session) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };

		for (const auto& workspace : workspaces_)
		{
			bool methods_match = false;
			bool header_match = false;
			bool path_match = false;

			if (workspace.second->methods().empty() == false)
			{
				for (const auto& method : workspace.second->methods())
				{
					if (session.request().method() == method)
					{
						methods_match = true;
						break;
					}
				}
			}
			else
			{
				methods_match = true;
			}

			if (methods_match && workspace.second->headers().empty() == false)
			{
				for (const auto& header : workspace.second->headers())
				{
					//bool found = false;
					//if (session.request().get<std::string>(header.name, found, "") == header.value && found == true)

					if (session.request().get<std::string>(header.name, "") == header.value)
					{
						header_match = true;
						break;
					}
				}
			}
			else
			{
				header_match = methods_match;
			}

			if (header_match && workspace.second->paths().empty() == false)
			{
				for (const auto& workspace_path : workspace.second->paths())
				{
					if (session.request().url_requested().find(workspace_path) == 0)
					{
						path_match = true;
						break;
					}
				}
			}
			else
			{
				path_match = header_match;
			}

			if (methods_match && header_match && path_match)
			{
				workspace.second->proxy_pass(session);
				break;
			}
		}
	}

	template <class M> bool select(const std::string& workspace_id, const M method, std::string& error_message) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };
		auto workspace = workspaces_.find(workspace_id);

		if (workspace != workspaces_.end())
		{
			return method(*workspace->second, error_message);
		}
		else
		{
			error_message = workspace_id + " does not exists in workspace collection";
		}
		return false;
	}

	template <class M> bool change(const std::string& workspace_id, const M method, std::string& error_message)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		auto workspace = workspaces_.find(workspace_id);

		if (workspace != workspaces_.end())
		{
			auto result = method(*workspace->second, error_message);
			is_changed(result);
			return result;
		}
		else
		{
			error_message = workspace_id + " does not exist in workspace collection";
		}
		return false;
	}

	template <class M>
	bool select(
		const std::string& workspace_id,
		const std::string& workgroup_name,
		const M method,
		std::string& error_message) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };
		auto workspace = workspaces_.find(workspace_id);

		if (workspace != workspaces_.end() && workspace->second->state() == workspace::state::up)
		{
			std14::shared_lock<mutex_type> g{ workspace->second->workgroups_mutex() };
			for (const auto& workgroup : *(workspace->second))
			{
				if ((workgroup.first == workgroup_name) && (workgroup.second->state() == workgroup::state::up))
					return method(*workgroup.second, error_message);
			}
			error_message = workgroup_name + " does not exists in workgroup collection ";
		}
		else
		{
			error_message = workspace_id + " does not exist in workspace collection";
		}
		return false;
	}

	template <class M>
	bool change(
		const std::string& workspace_id, const std::string& workgroup_name, const M method, std::string& error_message)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		auto workspace = workspaces_.find(workspace_id);

		if (workspace != workspaces_.end())
		{
			std::unique_lock<mutex_type> g{ workspace->second->workgroups_mutex() };

			for (auto& workgroup : *(workspace->second))
			{
				if ((workgroup.first == workgroup_name))
				{
					auto result = method(*workgroup.second, error_message);
					is_changed(result);
					workgroup.second->is_changed(result);
					return result;
				}
			}
			error_message = workgroup_name + " does not exist in workgroup collection";
		}
		else
		{
			error_message = workspace_id + " does not exist in workspace collection";
		}

		return false;
	}

	template <class M>
	bool select(
		const std::string& workspace_id,
		const std::string& workgroup_name,
		const std::string& worker_id,
		const M method,
		std::string& error_message) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };

		auto workspace = workspaces_.find(workspace_id);
		if (workspace != workspaces_.end() && workspace->second->state() == workspace::state::up)
		{
			std14::shared_lock<mutex_type> g{ workspace->second->workgroups_mutex() };
			for (const auto& workgroup : *(workspace->second))
			{
				if ((workgroup.first == workgroup_name) && (workgroup.second->state() == workgroup::state::up))
				{
					for (const auto& worker : *(workgroup.second))
					{
						if (worker.first == worker_id) return method(worker.second, error_message);
					}
				}
				error_message = worker_id + " does not exist in workers collection";
			}
			if (error_message.empty()) error_message = workgroup_name + " does not exist in workgroup collection";
		}
		else
		{
			error_message = workspace_id + " does not exist in workspace collection";
		}
		return false;
	}

	template <class M>
	bool change(
		const std::string& workspace_id,
		const std::string& workgroup_name,
		const std::string& worker_id,
		const M method,
		std::string& error_message) const
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		auto workspace = workspaces_.find(workspace_id);
		if (workspace != workspaces_.end())
		{
			std::unique_lock<mutex_type> g{ workspace->second->workgroups_mutex() };
			for (const auto& workgroup : *(workspace->second))
			{
				if ((workgroup.first == workgroup_name))
				{

					std::unique_lock<mutex_type> g{ workgroup.second->workers_mutex() };
					for (auto& worker : *(workgroup.second))
					{
						if (worker.first == worker_id) 
						{
							auto result = method(worker.second, error_message);
							workgroup.second->is_changed(result);
							return result;
						}
					}
					error_message = worker_id + " does not exist in workers collection";
				}
			}
			if (error_message.empty()) error_message = workgroup_name + " does not exist in workgroup collection";
		}
		else
		{
			error_message = workspace_id + " does not exist in workspace collection";
			return false;
		}
	}

	void to_json(json& j, output_formating::options options = output_formating::options::complete) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };

		j = json::array();

		for (auto& workspace : workspaces_)
		{
			auto workspace_json = json{};
			workspace.second->to_json(workspace_json, options);
			j.emplace_back(workspace_json);
		}
	}

	void from_json(const json& j)
	{
		for (auto& el : j.items())
		{
			add_workspace(el.value()["id"], el.value());
		}
	}
};

inline void to_json(json& j, const workspaces& ws) { ws.to_json(j); }
inline void from_json(const json& j, workspaces& ws) { ws.from_json(j); }



template <typename S> class director : public S
{
protected:
	using server_base = S;

private:
	//workspaces workspaces_;
	//std::thread director_thread_;

	std::string configuration_file_;

public:
	director(http::configuration& http_configuration, const std::string& configuration_file)
		: http::async::server(http_configuration), configuration_file_(configuration_file)
	{
		std::ifstream configuration_stream{ configuration_file_ };

		auto configfile_available = configuration_stream.fail() == false;

		if (configfile_available)
		{
			try
			{
				json manager_configuration_json = json::parse(configuration_stream);
				if (manager_configuration_json.contains("workspaces") == true)
					workspaces_.from_json(manager_configuration_json.at("workspaces"));
			}
			catch (json::parse_error& e)
			{
				if (e.id == 101 && e.byte == 1) // accept empty file
				{
					workspaces_.from_json(json::object());
				}
				else
				{
					server_base::logger_.api(
						"error when reading configuration ({s}) : {s}\n", configuration_file_, e.what());
					std::cout << "error when reading configuration (" << configuration_file_ << ") : " << e.what()
							  << std::endl;
					exit(-1);
				}
			}
		}
		else
		{
			//workspaces_.from_json(json::object());
		}

		server_base::router_.on_get(
			http::server::configuration_.get<std::string>("health_check", "/internal/platform/director/health_check"),
			[this](http::session_handler& session) {
				session.response().assign(http::status::ok, "OK");
				server_base::manager().update_health_check_metrics();
			});

		server_base::router_.on_post(
			"/internal/platform/director/access_log_level", [this](http::session_handler& session) {
				server_base::logger_.set_access_log_level(session.request().body());
				auto new_level = server_base::logger_.current_access_log_level_to_string();
				http::server::configuration_.set("access_log_level", new_level);
				session.response().body() = server_base::logger_.current_access_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_get(
			"/internal/platform/director/access_log_level", [this](http::session_handler& session) {
				session.response().body() = server_base::logger_.current_access_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_post(
			"/internal/platform/director/extended_log_level", [this](http::session_handler& session) {
				server_base::logger_.set_extended_log_level(session.request().body());
				auto new_level = server_base::logger_.current_extended_log_level_to_string();
				http::server::configuration_.set("extended_log_level", new_level);
				session.response().body() = server_base::logger_.current_extended_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_get(
			"/internal/platform/director/extended_log_level", [this](http::session_handler& session) {
				session.response().body() = server_base::logger_.current_extended_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_get("/internal/platform/director/status", [this](http::session_handler& session) {
			const auto& format = session.request().get<std::string>("Accept", "application/json");
			const auto& format_from_query_parameter = session.request().query().get<std::string>("format", "text");

			if (format.find("application/json") != std::string::npos || format_from_query_parameter == "json")
			{
				session.response().assign(
					http::status::ok,
					server_base::manager().to_json(http::server::server_manager::json_status_options::full).dump(),
					"json");
			}
			else
			{
				server_base::manager().server_information(http::server::configuration_.to_string());
				server_base::manager().router_information(server_base::router_.to_string());
				session.response().body() = server_base::manager().to_string();
				session.response().type("text");
			}

			session.response().status(http::status::ok);
		});

		server_base::router_.on_get(
			"/internal/platform/director/status/{section}", [this](http::session_handler& session) {
				const auto& format = session.request().get<std::string>("Accept", "application/json");
				const auto& format_from_query_parameter = session.request().query().get<std::string>("format", "text");
				const auto& section = session.params().get("section");

				if (section == "metrics")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::server_metrics)
							.dump(),
						"json");
				}
				else if (section == "configuration")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::config)
							.dump(),
						"json");
				}
				else if (section == "router")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::router)
							.dump(),
						"json");
				}
				else if (section == "access_log")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::access_log)
							.dump(),
						"json");
				}
				else if (section == "version")
				{
					std::string version = std::string{ "eln_cpd_" } + get_version_ex(PORT_SET, NULL)
										  + std::string{ "_" } + get_version_ex(PORT_NO, NULL);

					if (format.find("application/json") != std::string::npos || format_from_query_parameter == "json")
					{
						auto result = json::object();
						result["version"] = version;

						session.response().assign(http::status::ok, result.dump(), "json");
					}
					else
					{
						session.response().assign(http::status::ok, std::move(version), "text");
					}
				}
				else
				{
					session.response().assign(http::status::not_found);
				}
			});

	}
};

std::unique_ptr<cloud::platform::director<http::async::server>> eln_cpd_server_;

} // namespace platform
} // namespace cloud

inline bool start_eln_cpd_server(
	std::string config_file,
	std::string config_options,
	bool run_as_daemon,
	bool run_selftests,
	std::string selftest_options)
{
	std::string server_version = std::string{ "eln_cpd" };

	if (run_as_daemon) util::daemonize("/tmp", "/var/lock/" + server_version + ".pid");

	http::configuration http_configuration{ { { "server", server_version },
											  { "http_listen_port_begin", "4000" },
											  { "private_base", "/internal/platform/director" },
											  { "health_check", "/internal/platform/director/healthcheck" },
											  { "private_ip_white_list", "::/0" },
											  { "public_ip_white_list", "::/0" },
											  { "access_log_level", "access_log" },
											  { "access_log_file", "access_log.txt" },
											  { "extended_log_level", "api" },
											  { "extended_log_file", "console" },
											  { "https_enabled", "false" },
											  { "http_enabled", "true" },
											  { "http_use_portsharding", "false" } },
											config_options };

	if (run_selftests)
	{
		config_file = "selftest-" + std::to_string(getpid()) + ".json";
	}

	cloud::platform::eln_cpd_server_ = std::unique_ptr<cloud::platform::director<http::async::server>>(
		new cloud::platform::director<http::async::server>(http_configuration, config_file));

	auto result = cloud::platform::eln_cpd_server_->start() == http::server::state::active;

	if (run_selftests)
	{
		tests::test_base test{ http_configuration.get<std::string>(
								   "http_this_server_local_url", "http://localhost:4000"),
							   tests::configuration({}, std::string{ selftest_options }) };

		result = test.run();
	}

	return result;
}

inline bool start_eln_cpd_server(int argc, const char** argv)
{
	prog_args::arguments_t cmd_args(
		argc,
		argv,
		{ { "config",
			{ prog_args::arg_t::arg_val, " <config>: filename for the workspace config file or url", "config.json" } },
		  { "options", { prog_args::arg_t::arg_val, "<options>: see doc.", "" } },
		  { "daemonize", { prog_args::arg_t::flag, "run daemonized" } },
		  { "selftests", { prog_args::arg_t::flag, "run selftests" } },
		  { "selftests_options", { prog_args::arg_t::arg_val, "<options>: see doc." } }});

	if (cmd_args.process_args() == false)
	{
		std::cout << "error in arguments \n";
		exit(1);
	}

	return start_eln_cpd_server(
		cmd_args.get_val("config"),
		cmd_args.get_val("options"),
		cmd_args.get_val("daemonize") == "true",
		cmd_args.get_val("selftests") == "true",
		cmd_args.get_val("selftests_options"));

	return false;
}

inline void run_eln_cpd_server() {}

inline int stop_eln_cpd_server() { return 0; }