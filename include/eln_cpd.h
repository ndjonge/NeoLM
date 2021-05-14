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
			//try
			//{
			//	json manager_configuration_json = json::parse(configuration_stream);
			//	if (manager_configuration_json.contains("workspaces") == true)
			//		workspaces_.from_json(manager_configuration_json.at("workspaces"));
			//}
			//catch (json::parse_error& e)
			//{
			//	if (e.id == 101 && e.byte == 1) // accept empty file
			//	{
			//		workspaces_.from_json(json::object());
			//	}
			//	else
			//	{
			//		server_base::logger_.api(
			//			"error when reading configuration ({s}) : {s}\n", configuration_file_, e.what());
			//		std::cout << "error when reading configuration (" << configuration_file_ << ") : " << e.what()
			//				  << std::endl;
			//		exit(-1);
			//	}
			//}
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