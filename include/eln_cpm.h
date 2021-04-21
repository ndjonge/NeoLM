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

#ifndef LOCAL_TESTING
#include "baanlogin.h"
#include "bdaemon.h"
#include <curl/curl.h>

#ifdef _WIN32
#include "sspisecurity.h"
#include <direct.h>
#include <process.h>
#define HOST_NAME_MAX 256
#else
#include <unistd.h>
#endif

#else
#define get_version_ex(PORT_SET, NULL) "1.0"
#define BAAN_WINSTATION_NAME "baan"
#define BAAN_DESKTOP_NAME "desktop"
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
	template <typename S> class worker : public S, public cloud::platform::enable_server_as_worker<nlohmann::json>
	{
	protected:
		using server_base = S;

	public:
		worker(http::configuration& http_configuration)
			: server_base(http_configuration), cloud::platform::enable_server_as_worker<nlohmann::json>(this)
		{
			server_base::router_.on_get(
				http::server::configuration_.get<std::string>("health_check", "/private/health_check"),
				[this](http::session_handler& session) {
					session.response().assign(http::status::ok, "OK");
					server_base::manager().update_health_check_metrics();
				});

			server_base::router_.on_post("/internal/platform/worker/mirror", [](http::session_handler& session) {
				session.response().status(http::status::ok);
				session.response().type(session.response().get<std::string>("Content-Type", "text/plain"));
				session.response().body() = session.request().body();
				});

			server_base::router_.on_post(
				"/internal/platform/worker/access_log_level", [this](http::session_handler& session) {
					server_base::logger_.set_access_log_level(session.request().body());
					auto new_level = server_base::logger_.current_access_log_level_to_string();
					http::server::configuration_.set("access_log_level", new_level);
					session.response().body() = server_base::logger_.current_access_log_level_to_string();
					session.response().status(http::status::ok);
				});

			server_base::router_.on_get(
				"/internal/platform/worker/access_log_level", [this](http::session_handler& session) {
					session.response().body() = server_base::logger_.current_access_log_level_to_string();
					session.response().status(http::status::ok);
				});

			server_base::router_.on_post(
				"/internal/platform/worker/extended_log_level", [this](http::session_handler& session) {
					server_base::logger_.set_extended_log_level(session.request().body());
					auto new_level = server_base::logger_.current_extended_log_level_to_string();
					http::server::configuration_.set("extended_log_level", new_level);
					session.response().body() = server_base::logger_.current_extended_log_level_to_string();
					session.response().status(http::status::ok);
				});

			server_base::router_.on_get(
				"/internal/platform/worker/extended_log_level", [this](http::session_handler& session) {
					session.response().body() = server_base::logger_.current_extended_log_level_to_string();
					session.response().status(http::status::ok);
				});

			server_base::router_.on_get("/internal/platform/worker/status", [this](http::session_handler& session) {
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
				"/internal/platform/worker/status/{section}", [this](http::session_handler& session) {
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
						std::string version = std::string{ "cld_wrk " } + get_version_ex(PORT_SET, NULL)
							+ std::string{ "/" } + get_version_ex(PORT_NO, NULL);

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

			server_base::router_.on_delete("/internal/platform/worker/process",
				[this](http::session_handler& session) {
					session.response().status(http::status::no_content);
					session.response().body() = std::string("");
					session.response().set("Connection", "close");

					server_base::deactivate();
				});


			server_base::router_.on_post(
				"/internal/platform/worker/watchdog",
				[this](http::session_handler& session) {
					server_base::manager().idle_time_reset();
					session.response().status(http::status::ok);
				});

			server_base::router_.on_idle([this](bool is_idle_timeout_execeeded) {
				if (is_idle_timeout_execeeded == true)
				{
					server_base::deactivate();
				}
				else
				{
					server_base::logger_.info("idle \n {s} \n", server_base::manager().to_string());
				}
				});


		}

		virtual ~worker() {}

		http::server::state start() override
		{
			try
			{
				auto ret = server_base::start();

				if (ret == http::server::state::active && workgroup_controller_)
					workgroup_controller_->add();

				return ret;
			}
			catch (std::runtime_error& e)
			{
				std::cerr << e.what() << std::endl;
				_exit(-1);
			}
		}
	};

	static std::unique_ptr<worker<http::sync::server>> cld_wrk_server_;

	inline bool start_cld_wrk_server(std::string config_options, bool run_as_daemon)
	{
		std::string server_version = std::string{ "ln-cld-wrk" };

		if (run_as_daemon) util::daemonize("/tmp", "/var/lock/" + server_version + ".pid");

		http::configuration http_configuration{
			{ { "server", server_version },
			  { "http_listen_port_begin", "0" },
			  { "http_watchdog_idle_timeout", "20"},
			  { "private_base", "/internal/platform/worker" },
			  { "health_check", "/internal/platform/worker/healthcheck" },
			  { "private_ip_white_list", "::/0" },
			  { "public_ip_white_list", "::/0" },
			  { "access_log_level", "access_log" },
			  { "access_log_file", "access_log.txt" },
			  { "extended_log_level", "none" },
			  { "extended_log_file", "extended_log.txt" },
			  { "https_enabled", "false" },
			  { "http_enabled", "true" },
			  { "http_use_portsharding", "false" } },
			config_options
		};

		cld_wrk_server_ = std::unique_ptr<worker<http::sync::server>>(
			new worker<http::sync::server>(http_configuration));

		auto result = cld_wrk_server_->start() == http::server::state::active;

		return result;
	}

	inline bool start_cld_wrk_server(int argc, const char** argv)
	{
		prog_args::arguments_t cmd_args(
			argc,
			argv,
			{ { "httpserver_options", { prog_args::arg_t::arg_val, "see doc.", "" } },
			  { "daemonize", { prog_args::arg_t::flag, "run daemonized" } } });

		if (cmd_args.process_args() == false)
		{
			std::cout << "error in arguments \n";
			exit(1);
		}

		return start_cld_wrk_server(
			cmd_args.get_val("httpserver_options"),
			cmd_args.get_val("daemonize") == "true");
	}

	inline void run_cld_wrk_server()
	{
		while (cld_wrk_server_->is_active())
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}

	inline int stop_cld_wrk_server()
	{
		cld_wrk_server_->stop();
		cld_wrk_server_.release();
		return 0;
	}




	inline bool add_workspace(std::string workspace_id, std::string tenant_id)
	{
		json workspace_def{ { "workspace",
							  { { "id", workspace_id },
								{ "routes",
								  { { "paths", { "/api", "/internal" } },
									{ "methods", { "get", "head", "post" } },
									{ "headers", { { "X-Infor-TenantId", { tenant_id } } } } } } } } };
		//,
		//{ "workgroups",
		//  { { { "name", "service_a000" },
		//	  { "type", "bshells" },
		//	  { "routes",
		//	{ { "paths", { "/tests", "/platform" } },
		//		  { "methods", { "get", "head", "post" } },
		//		  { "headers", { { "X-Infor-Company", { id } } } } } },
		//	  { "limits",
		//		{ { "workers_min", 4 },
		//		  { "workers_max", 8 },
		//		  { "workers_required", 4 },
		//		  { "workers_start_at_once_max", 8 } } },
		//	  { "parameters", { "program", "bshell" } } } } } } } };

		//	std::cout << workspace_def.dump(4, ' ') << "\n";
		std::string error;

		auto response = http::client::request<http::method::post>(
			"http://localhost:4000/internal/platform/manager/workspaces", error, {}, workspace_def["workspace"].dump());

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool add_workgroup(std::string workspace_id, std::string workgroup_name, int required, int start_at_once)
	{

		json workgroup_def{ { "name", workgroup_name },
							{ "type", "bshells" },
	#ifdef _WIN32
							{ "parameters", {{  "program", "eln_cpm.exe" } , { "cli_options", "-selftests_worker" }} },
	#else
		{ "parameters", { { "program", "eln_cpm" } , { "cli_options", "-selftests_worker" }} },
	#endif
							{ "limits",
							  { { "workers_min", required },
								{ "workers_max", 16 },
								{ "workers_required", required },
								{ "workers_start_at_once_max", start_at_once } } } };

		// std::cout << workgroup_def.dump(4, ' ') << "\n";

		std::string error;

		auto response = http::client::request<http::method::post>(
			"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id + "/workgroups",
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
			"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id + "/workgroups/" + workgroup_name
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
			"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id + "/workgroups/" + workgroup_name,
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
			"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id, error, {});

		if (error.empty() == false) return false;

		if (response.status() == http::status::conflict)
		{
		}

		return true;
	}

	inline bool generate_proxied_requests(const std::string& request_url, std::string tenant, int count)
	{
		std::thread{ [count, request_url, tenant]() {
			for (int i = 0; i != count; i++)
			{
				std::string error;
				auto response = http::client::request<http::method::get>(
					"http://localhost:4000" + request_url,
					error,
					{ { "X-Infor-TenantId", tenant } },
					{});

				if (response.status() == http::status::not_found)
				{
				}
				else
				{
				}
			}
		} }.detach();

		return true;
	}

	inline bool generate_proxied_requests(const std::string& request_url, int count)
	{
		std::thread{ [count, request_url]() {
			for (int i = 0; i != count; i++)
			{
				std::string error;
				auto response = http::client::request<http::method::get>(
					"http://localhost:4000" + request_url, error, {}, {});

				if (response.status() == http::status::not_found)
				{
				}
				else
				{
				}
			}
		} }.detach();

		return true;
	}

	inline bool run(
		const int workspace_count = 1,
		const int workgroup_count = 1,
		const int run_count = -1,
		const int worker_count = 0,
		const int worker_start_at_once_count = 4,
		const int requests_count = 30,
		const int stay_alive_time = 30)
	{

		for (int n = 0; n != run_count; n++)
		{
			for (int i = 0; i < workspace_count; i++)
				tests::add_workspace("workspace_" + std::to_string(100 + i), "tenant" + std::to_string(100 + i) + "_tst");

			for (int j = 0; j < workspace_count; j++)
				for (int i = 0; i < workgroup_count; i++)
					tests::add_workgroup("workspace_" + std::to_string(100 + j),
						"workgroup_" + std::to_string(i),
						worker_count,
						worker_start_at_once_count);

			for (int j = 0; j < workspace_count; j++)
				for (int i = 0; i < workgroup_count; i++)
					tests::increase_workgroup_limits(
						"workspace_" + std::to_string(100 + j), "workgroup_" + std::to_string(i), worker_count);

			for (int i = 0; i < workspace_count; i++)
				tests::generate_proxied_requests(
					"/api/tests/1k", "tenant" + std::to_string(100 + i) + "_tst", requests_count);

			for (int i = 0; i < workspace_count; i++)
				tests::generate_proxied_requests("/internal/platform/manager/workspaces", requests_count);

			std::this_thread::sleep_for(std::chrono::seconds(stay_alive_time));

			for (int j = 0; j < workspace_count; j++)
				for (int i = 0; i < workgroup_count; i++)
					tests::remove_workgroup("workspace_" + std::to_string(100 + j), "workgroup_" + std::to_string(i));

			for (int i = 0; i < workspace_count; i++)
				tests::remove_workspace("workspace_" + std::to_string(100 + i));

			std::this_thread::sleep_for(std::chrono::seconds(10));
		}

		return true;
	}

} // namespace tests


namespace bse_utils
{

#ifdef LOCAL_TESTING_WITH_NGINX_BACKEND

	namespace local_testing
	{
		std::mutex m;

		template <typename S> struct test_sockets
		{
		public:
			std::map<std::string, std::set<S>> available_sockets_;
			std::mutex m_;

			test_sockets(const std::vector<std::string>& workspaces, S b, size_t nr) // 8000 64
			{
				for (auto& workspace : workspaces)
				{
					std::lock_guard<std::mutex> g{ m_ };
					for (S i = 0; i < nr; i++)
						available_sockets_[workspace].emplace(b + i);
				}
			}

			S aquire(const std::string& workspace_id)
			{
				std::lock_guard<std::mutex> g{ m_ };

				auto port = *(available_sockets_[workspace_id].begin());
				available_sockets_[workspace_id].erase(port);
				return port;
			}

			S aquire(const std::string& workspace_id, S port)
			{
				std::lock_guard<std::mutex> g{ m_ };

				available_sockets_[workspace_id].erase(port);

				return port;
			}

			void release(const std::string& workspace_id, const std::string& url)
			{
				std::lock_guard<std::mutex> g{ m_ };
				auto port = url.substr(1 + url.find_last_of(':'));

				available_sockets_[workspace_id].emplace(stoul(port));
			}
		};

		static test_sockets<std::uint32_t> _test_sockets{
			{ "workspace_000", "workspace_001", "workspace_002", "workspace_003", "workspace_100", "workspace_101",
			  "workspace_102", "workspace_103", "workspace_104", "workspace_105", "workspace_106", "workspace_107",
			  "workspace_108", "workspace_109", "workspace_110", "workspace_111", "workspace_112", "workspace_113",
			  "workspace_114", "workspace_115", "workspace_116", "workspace_117", "workspace_118", "workspace_119",
			  "workspace_120", "workspace_121", "workspace_122", "workspace_123", "workspace_124", "workspace_125",
			  "workspace_126", "workspace_127", "workspace_128", "workspace_129", "workspace_130", "workspace_131",
			  "workspace_132", "workspace_133", "workspace_134", "workspace_135", "workspace_136", "workspace_137",
			  "workspace_138", "workspace_139", "workspace_140", "workspace_141", "workspace_142", "workspace_143",
			  "workspace_144", "workspace_145", "workspace_146", "workspace_147", "workspace_148", "workspace_149",
			  "workspace_150", "workspace_151", "workspace_152", "workspace_153", "workspace_154", "workspace_155",
			  "workspace_156", "workspace_157", "workspace_158", "workspace_159", "workspace_160", "workspace_161",
			  "workspace_162", "workspace_163" },
			8000,
			64
		};

	} // namespace local_testing

	static bool create_bse_process_as_user(
		const std::string&,
		const std::string&,
		const std::string&,
		const std::string&,
		const std::string&,
		const std::string& parameters, // for local testing retreive the level this way :(
		std::uint32_t& pid,
		std::string& ec)
	{
		bool result = true;

		auto parameters_as_configuration = http::configuration({}, parameters);

		auto worker_id = parameters_as_configuration.get("cpm_worker_id");
		auto worker_label = parameters_as_configuration.get("cpm_worker_label");
		auto worker_workspace = parameters_as_configuration.get("cpm_workspace");
		auto worker_workgroup = parameters_as_configuration.get("cpm_workgroup");

		pid = local_testing::_test_sockets.aquire(worker_workspace);

		ec = "";

		std::thread([pid, worker_workspace, worker_label, worker_workgroup, worker_id]() {
			std::lock_guard<std::mutex> g{ local_testing::m };
			json put_new_instance_json = json::object();
			std::string ec;
			put_new_instance_json["process_id"] = pid;
			put_new_instance_json["worker_id"] = worker_id;
			put_new_instance_json["worker_label"] = worker_label;
			put_new_instance_json["base_url"] = "http://localhost:" + std::to_string(pid);
			put_new_instance_json["version"] = "test_bshell";

			auto response = http::client::request<http::method::post>(
				"http://localhost:4000/internal/platform/manager/workspaces/" + worker_workspace + "/workgroups/"
				+ worker_workgroup + "/workers",
				ec,
				{},
				put_new_instance_json.dump()); //,std::cerr, true);

			if (ec.empty())
			{
				if (response.status() != http::status::ok && response.status() != http::status::created
					&& response.status() != http::status::no_content && response.status() != http::status::conflict)
				{
					//throw std::runtime_error{ "error sending \"worker\" registration" };
				}
			}
			else
				throw std::runtime_error{ "error sending \"worker\" registration" };
			}).detach();

			pid = pid + 1;
			return result;
	}

#else
	static bool create_bse_process_as_user(
		const std::string& bse,
		const std::string& bse_bin,
		const std::string& tenand_id,
		const std::string& user,
		const std::string& password,
		const std::string& command,
		std::uint32_t& pid,
		std::string& ec)
	{
		bool result = false;

#ifndef _WIN32
		// If user is empty then start process as same user
#ifndef LOCAL_TESTING
		auto user_ok = (user.empty() && password.empty()) || CheckUserInfo(user.data(), password.data(), NULL, 0, NULL, 0);
#else
		auto user_ok = user.empty() && password.empty();
#endif
#else
		HANDLE requested_user_token = 0;
		auto user_ok = false;
		if (user.empty() && password.empty())
		{
			user_ok = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &requested_user_token);
		}
		else
		{
#ifndef LOCAL_TESTING
			user_ok = CheckUserInfo(
				user.data(), password.data(), NULL, 0, NULL, 0, &requested_user_token, eWindowsLogonType_Default);
#else
			user_ok = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &requested_user_token);
#endif
		}

		if (!user_ok)
		{
			// TODO more info about failure.
			ec = "login as user: " + user + " failed";
			result = false;
		}
		else
		{
			char desktop[MAX_PATH];
			const char* required_environment_vars[]
				= { "ALLUSERSPROFILE", "CLASSPATH",	 "CLASSPATH", "SLMHOME", "SLM_RUNTIME",
					"SystemDrive",	   "SystemRoot", "WINDIR",	  "TMP",	 "TEMP" };

			std::string environment_block;
			std::stringstream ss;

			ss << "BSE=" << bse << char{ 0 };
			ss << "BSE_BIN=" << bse_bin << char{ 0 };
			ss << "BSE_SHLIB=" << bse_bin << "\\..\\shlib" << char{ 0 };
			ss << "TENAND_ID=" << tenand_id << char{ 0 };

			for (auto var : required_environment_vars)
			{
				if (getenv(var))
				{
					ss << var << "=" << getenv(var) << char{ 0 };
				}
			}
			ss << char{ 0 };

			PROCESS_INFORMATION piProcInfo = { };
			STARTUPINFO siStartInfo{ };

			std::memset(&piProcInfo, 0, sizeof(PROCESS_INFORMATION));
			std::memset(&siStartInfo, 0, sizeof(STARTUPINFO));

			siStartInfo.cb = sizeof(STARTUPINFO);

			auto error = GetLastError();

			auto cwd = bse.data();

			if (bse.empty())
			{
				cwd = nullptr; // use current workdir
			}
			else
			{
				snprintf(desktop, sizeof(desktop), "%s\\%s", BAAN_WINSTATION_NAME, BAAN_DESKTOP_NAME);
				siStartInfo.lpDesktop = desktop;
			}


			std::string command_cpy = command;

			if (user.empty())
			{
				error = 0;
				result = CreateProcess(
					cwd,
					const_cast<LPSTR>(command_cpy.data()),
					NULL,
					NULL,
					FALSE,
					CREATE_NEW_PROCESS_GROUP | /* New root process */
					DETACHED_PROCESS | /* Create NO console!! */
					CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
					NULL,
					NULL,
					&siStartInfo,
					&piProcInfo
				);
			}
			else
			{

				error = 0;
				result = CreateProcessAsUser(
					requested_user_token, /* Handle to logged-on user */
					NULL, /* module name */
					const_cast<LPSTR>(command_cpy.data()), /* command line */
					NULL, /* process security attributes */
					NULL, /* thread security attributes */
					FALSE, /* inherits handles */
					CREATE_NEW_PROCESS_GROUP | /* New root process */
					DETACHED_PROCESS | /* Create NO console!! */
					CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
					const_cast<LPSTR>(ss.str().data()), /* new environment block */
					cwd, /* current working directory name */
					&siStartInfo,
					&piProcInfo /* Returns thread */
				);
			}


			if (result)
			{
				pid = piProcInfo.dwProcessId;

				if (1)
					std::cout << "worker_command: " << command_cpy << "\n";
			}
			else
			{
				char buf[256];
				FormatMessage(
					FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					GetLastError(),
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					buf,
					(sizeof(buf) / sizeof(char)),
					NULL);

				ec.assign(buf, std::strlen(buf));
				ec += "\n running this command: (" + command_cpy + ")";
			}


			CloseHandle(piProcInfo.hThread);
			CloseHandle(piProcInfo.hProcess);

			if (user.empty() == false)
			{
				RevertToSelf();
				CloseHandle(requested_user_token);
			}
		}
#endif

#ifndef _WIN32
		if (!user_ok)
		{
			// TODO more info about failure.
			ec = "login as user: " + user + " failed";
			result = false;
		}
		else
		{
			std::vector<char*> argv;
			auto command_args = util::split(command.data(), " ");

			for (auto& arg : command_args)
			{
				size_t arg_1_size = strlen(arg.c_str());
				char* arg_1 = new char[arg_1_size + 1];
				std::strncpy(arg_1, arg.c_str(), arg_1_size);
				arg_1[arg_1_size] = 0;
				argv.push_back(arg_1);
			}

			argv.push_back(nullptr);

			// TODO required_environment_vars not needed to start process in (tenant) jail.
			const char* required_environment_vars[] = { "PATH",		 "CLASSPATH",	 "CLASSPATH", "SLMHOME", "SLM_RUNTIME",
														"SLM_DEBUG", "SLM_DEBUFILE", "HOSTNAME",  "TMP",	 "TEMP" };

			std::vector<char*> envp;

			std::string environment_block;
			std::stringstream ss;

			if (bse != "")
			{
				ss << "BSE=" << bse << char{ 0 };
				envp.push_back(strdup(ss.str().data()));
				std::stringstream().swap(ss);
			}

			if (bse_bin != "")
			{
				ss << "BSE_BIN=" << bse_bin << char{ 0 };
				envp.push_back(strdup(ss.str().data()));
				std::stringstream().swap(ss);

				ss << "BSE_SHLIB=" << bse_bin << "/../shlib" << char{ 0 };
				envp.push_back(strdup(ss.str().data()));
				std::stringstream().swap(ss);

				ss << "SYSTEMLIBDIR64=" << bse_bin << "/../shlib:" << getenv("SYSTEMLIBDIR64") << char{ 0 };
				envp.push_back(strdup(ss.str().data()));
				std::stringstream().swap(ss);
			}

			for (auto var : required_environment_vars)
			{
				if (getenv(var))
				{
					ss << var << "=" << getenv(var) << char{ 0 };
					envp.push_back(strdup(ss.str().data()));
					std::stringstream().swap(ss);
				}
			}
			envp.push_back(strdup(ss.str().data()));
			envp.push_back(nullptr);

			signal(SIGCHLD, SIG_IGN);

			pid = fork();

			if (pid == 0)
			{
				// close all fd in the forked child.
				int fdlimit = (int)sysconf(_SC_OPEN_MAX);
				for (int i = STDERR_FILENO + 1; i < fdlimit; i++)
					close(i);

				if (user != "")
				{
#if !defined(LOCAL_TESTING)
					if (ImpersonateUser(user.data(), NULL, 0, NULL) == -1)
#else
					if (true)
#endif
					{

						printf("error on impersonating user %s, error :%d\n", user.data(), errno);
						_exit(1);
					}
				}

				if (execve(argv[0], &argv[0], envp.data()) == -1)
				{
					printf("error on execve: %d\n", errno);
					_exit(1);
				}
			}
			else
			{
				for (auto env_var : envp)
				{
					free(env_var);
				}
				result = true;
			}
		}
#endif
		return result;
	}
#endif

} // namespace bse_utils

namespace cloud
{

	namespace platform
	{

		class workspace;
		class workgroups;
		class workspaces;

		namespace output_formating
		{

			enum class options
			{
				complete,
				essential
			};

		}
		void to_json(json& j, const workspace& value);
		void from_json(const json& j, workspace& value);

		void to_json(json& j, const workgroups& v);
		void from_json(const json& j, workgroups& v);

		void to_json(json& j, const workspaces&);
		void from_json(const json& j, workspaces&);

		class worker
		{
		public:
			enum class status
			{
				recover,
				starting,
				up,
				drain,
				down
			};

			static std::string to_string(worker::status status)
			{
				switch (status)
				{
				case status::recover:
					return "recover";
				case status::starting:
					return "starting";
				case status::down:
					return "down";
				case status::up:
					return "up";
				case status::drain:
					return "drain";
				default:
					return "-";
				}
			}

		private:
			std::string worker_id_{};
			std::string worker_label_{};
			std::string base_url_{};
			std::string version_{};
			std::int32_t process_id_;
			std::chrono::steady_clock::time_point startup_t0_;
			std::chrono::steady_clock::time_point startup_t1_{};

			std::atomic<status> status_{ status::down };
			json worker_metrics_{};
			http::async::upstreams::upstream* upstream_{ nullptr };

		public:
			worker(
				std::string worker_id,
				std::string worker_label,
				std::string base_url = "",
				std::string version = "",
				std::int32_t process_id = 0)
				: worker_id_(worker_id)
				, worker_label_(worker_label)
				, base_url_(base_url)
				, version_(version)
				, process_id_(process_id)
				, startup_t0_(std::chrono::steady_clock::now())
				, status_(worker::status::starting)
			{
			}

			worker(const worker& worker)
				: worker_id_(worker.worker_id_)
				, worker_label_(worker.worker_label_)
				, base_url_(worker.base_url_)
				, version_(worker.version_)
				, process_id_(worker.process_id_)
				, startup_t0_(worker.startup_t0_)
				, status_(worker.status_.load())
			{
			}

			virtual ~worker() { worker_metrics_.clear(); }

			void upstream(http::async::upstreams::upstream& upstream) { upstream_ = &upstream; }
			const http::async::upstreams::upstream& upstream() const { return *upstream_; }

			const std::string& get_base_url() const { return base_url_; }
			const std::string& worker_label() const { return worker_label_; }

			void worker_label(const std::string& level) { worker_label_ = level; }

			int get_process_id() const { return process_id_; };

			status get_status() const { return status_; }
			void set_status(status s)
			{
				if (status_ == status::starting && (s == status::up || s == status::recover))
				{
					startup_t1_ = std::chrono::steady_clock::now();
				}
				else if (upstream_ && s == status::drain)
				{
					upstream_->set_state(http::async::upstreams::upstream::state::drain);
				}
				else if (
					(upstream_ == nullptr) && (s == status::drain && ((status_ == status::recover) || (status_ == status::starting))))
				{
					return;
				}

				status_ = s;
			};

			void from_json(const json& worker_json)
			{
				process_id_ = worker_json.value("process_id", 0);
				base_url_ = worker_json.value("base_url", "");
				version_ = worker_json.value("version", "");
				worker_label_ = worker_json.value("worker_label", "");
			}

			void to_json(json& worker_json, output_formating::options) const
			{
				if (!base_url_.empty())
				{
					worker_json["link_to_status_url"] = base_url_ + "/internal/platform/worker/status";
					worker_json["base_url"] = base_url_;
					worker_json["version"] = version_;

					if (worker_metrics_.is_null() == false && worker_metrics_.size())
						for (auto metric = std::begin(worker_metrics_["metrics"]);
							metric != std::end(worker_metrics_["metrics"]);
							metric++)
							worker_json["metrics"][metric.key()] = metric.value();
				}
				worker_json["status"] = worker::to_string(get_status());
				worker_json["process_id"] = process_id_;
				worker_json["worker_id"] = worker_id_;
				worker_json["worker_label"] = worker_label_;

				if (status_ != status::down)
				{
					worker_json["startup_latency"]
						= std::chrono::duration_cast<std::chrono::milliseconds>(startup_t1_ - startup_t0_).count();

					worker_json["runtime"]
						= std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - startup_t1_)
						.count();
				}
			}

			int runtime() const
			{
				auto ret
					= std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - startup_t1_).count();

				return ret;
			}

			json get_worker_metrics(void) { return worker_metrics_; }
			void set_worker_metrics(json& j) { worker_metrics_ = std::move(j); }
		};

		//
		// Implementor
		//
		class workgroups
		{
		public:
			class limits;

			enum class state
			{
				down,
				up,
				drain
			};

			using container_type = std::map<const std::string, worker>;
			using iterator = container_type::iterator;
			using const_iterator = container_type::const_iterator;
			using mutex_type = std14::shared_mutex;

			workgroups(const std::string& workspace_id, const std::string& type)
				: workspace_id_(workspace_id), type_(type), state_(state::up)
			{
			}
			virtual ~workgroups() = default;

			mutex_type& workers_mutex() { return workers_mutex_; }

			const_iterator cbegin() const { return workers_.cbegin(); }
			const_iterator cend() const { return workers_.cend(); }
			iterator begin() { return workers_.begin(); }
			iterator end() { return workers_.end(); }

			void cleanup() {};

			http::async::upstreams upstreams_;

			bool has_workers_available() const { return limits_.workers_actual() > 0; }

			state state() const { return state_; }
			void state(const enum cloud::platform::workgroups::state& s) { state_ = s; }

			iterator find_worker(const std::string& worker_id)
			{
				std::unique_lock<mutex_type> g{ workers_mutex_ };
				return workers_.find(worker_id);
			}

			bool add_worker(
				const std::string& worker_id, const std::string& worker_label, const json& j, asio::io_context& io_context)
			{
				std::int32_t process_id;
				std::string base_url;
				std::string version;

				process_id = j.value("process_id", 0);
				base_url = j.value("base_url", "");
				version = j.value("version", "");

				auto new_worker = workers_.emplace(std::pair<const std::string, worker>(
					worker_id, worker{ worker_id, worker_label, base_url, version, process_id }));

				auto result = new_worker.second;

				if (new_worker.second == false) new_worker.first->second.from_json(j);

				if (base_url.empty() == false)
				{
					limits_.workers_actual_upd(1);
					auto& upstream = upstreams_.add_upstream(
						io_context, base_url, "/" + name_ + "/" + type_ + "/" + worker_id + "_" + worker_label);

					new_worker.first->second.upstream(upstream);
					new_worker.first->second.set_status(worker::status::up);

					result = true;
				}

				return result;
			}

			bool drain_all_workers()
			{
				bool result = false;

				for (auto& worker : workers_)
				{
					{
						std::string ec;
						auto response = http::client::request<http::method::delete_>(
							worker.second.get_base_url() + "/internal/platform/worker/process", ec, {});

						if (response.status() == http::status::no_content)
						{
							worker.second.set_status(worker::status::drain);
						}

						if (worker.second.get_status() == worker::status::drain)
							if (worker.second.upstream().connections_busy_.load() == 0)
								worker.second.set_status(worker::status::down);
					}
					result = true;
				}

				return result;
			}

			bool delete_worker(const std::string& id)
			{
				bool result = false;

				auto worker = workers_.find(id);
				if (worker != workers_.end())
				{
					if (worker->second.get_base_url().empty() == false)
					{
						worker->second.set_status(worker::status::drain);

						if (worker->second.upstream().connections_busy_.load() == 0)
							worker->second.set_status(worker::status::down);
					}
					result = true;
				}

				return result;
			}

			bool delete_worker_process(const std::string& id)
			{
				std::unique_lock<mutex_type> g{ workers_mutex_ };
				bool result = false;

				auto worker = workers_.find(id);

				if (worker != workers_.end())
				{
					std::string ec;
					auto response = http::client::request<http::method::delete_>(
						worker->second.get_base_url() + "/internal/platform/worker/process", ec, {});

					if (response.status() == http::status::no_content)
					{
						worker->second.set_status(worker::status::down);
						result = true;
					}
				}
				return result;
			}

		public:
			using route_methods_type = std::vector<http::method::method_t>;
			using route_path_type = std::vector<std::string>;
			using route_headers_type = std::vector<http::field<std::string>>;

		private:
			route_methods_type methods_;
			route_path_type paths_;
			route_headers_type headers_;
			mutex_type mutex;

		public:
			const route_path_type& paths() const { return paths_; }
			const route_headers_type& headers() const { return headers_; }
			const route_methods_type& methods() const { return methods_; }

			const std::string& get_type(void) const { return type_; }
			const std::string& get_name(void) const { return name_; }

			virtual void from_json(const json& j)
			{
				name_ = j.value("name", "anonymous");

				//"routes" : {
				//    "headers" : [ {"X-Infor-Tenant-Id" : "tenant100_tst"} ],
				//    "paths": [ "/api", "/internal" ]
				//},

				if (j.contains("routes"))
				{
					if (j["routes"].contains("headers"))
					{
						for (auto& header : j["routes"]["headers"].items())
						{
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

				if (j.contains("limits")) limits_.from_json(j["limits"]);
			}

			virtual void from_json(const json& j, const std::string& detail) = 0;
			virtual void to_json(json& j, const std::string& detail) const = 0;

			virtual void to_json(json& j, output_formating::options options) const
			{
				j["name"] = name_;
				j["type"] = type_;

				json limits_json;
				limits_.to_json(limits_json, options);
				j["limits"] = limits_json;
				j["workers"] = json::array();

				if (paths_.empty() == false)
				{
					for (const auto& paths : paths_)
						j["routes"]["paths"].emplace_back(paths);
				}

				if (headers_.empty() == false)
				{
					for (const auto& header : headers_)
						j["routes"]["headers"][header.name].emplace_back(header.value);
				}

				if (methods_.empty() == false)
				{
					for (const auto& method : methods_)
						j["routes"]["methods"].emplace_back(http::method::to_string(method));
				}

				// if (options == output_formating::options::complete)
				{
					std14::shared_lock<mutex_type> g{ workers_mutex_ };
					for (auto worker = workers_.cbegin(); worker != workers_.cend(); ++worker)
					{
						json worker_json;

						worker->second.to_json(worker_json, options);

						j["workers"].emplace_back(worker_json);
					}
				}
			}

			virtual bool create_worker_process(
				const std::string& manager_endpoint,
				const std::string& workspace_id,
				const std::string& worker_type,
				const std::string& worker_name,
				std::uint32_t& pid,
				std::string& worker_id,
				const std::string& worker_label,
				std::string& ec)
				= 0;

			void cleanup_all_workers(void)
			{
				for (auto in = workers_.begin(); in != workers_.end();)
				{
					in = workers_.erase(in);
				}
			}

			void remove_deleted_workers(void)
			{
				for (auto in = workers_.begin(); in != workers_.end();)
				{
					if (in->second.get_status() == worker::status::drain)
					{
						in = workers_.erase(in);
					}
					else
						in++;
				}
			}

			class limits
			{
			public:
				std::int16_t workers_pending() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_pending_;
				}
				std::int16_t workers_required() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_required_;
				}
				std::int16_t workers_required_to_add() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_required_ - (workers_actual_ + workers_pending_);
				}
				std::int16_t workers_actual() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_actual_;
				}
				std::int16_t workers_start_at_once_max()
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_start_at_once_max_;
				}
				std::int16_t workers_min() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_min_;
				}

				std::int16_t workers_runtime_max() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_runtime_max_;
				}

				std::int16_t workers_requests_max() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_requests_max_;
				}

				std::int16_t workers_max() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_max_;
				}
				const std::string& workers_label_actual() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_label_actual_;
				}
				const std::string& workers_label_required() const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					return workers_label_required_;
				}

				void workers_pending_upd(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_pending_ += value;
				}

				void workers_required(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_required_ = value;
				}
				void workers_required_upd(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_required_ += value;
				}
				void workers_actual(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_actual_ = value;
				}
				void workers_actual_upd(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					if (value > 0 && workers_pending_) workers_pending_ -= value;

					workers_actual_ += value;
				}
				void workers_min(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_min_ = value;
				}
				void workers_max(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_max_ = value;
				}

				void workers_label_required(const std::string& value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_label_required_ = value;
				}
				void workers_label_actual(const std::string& value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_label_actual_ = value;
				}

				void workers_not_on_label_required(std::int16_t value) { workers_not_on_label_required_ = value; }

				void workers_start_at_once_max(std::int16_t value)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					workers_start_at_once_max_ = value;
				}

				enum class from_json_operation
				{
					ignore,
					add,
					set
				};

				void from_json(
					const json& j, const std::string& limit_name = "", from_json_operation method = from_json_operation::set)
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };
					if (method == from_json_operation::set)
					{
						if (limit_name.empty() || limit_name == "workers_required")
							workers_required_ = j.value("workers_required", workers_min_);

						if (limit_name.empty() || limit_name == "workers_min")
							workers_min_ = j.value("workers_min", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_max")
							workers_max_ = j.value("workers_max", workers_min_);

						if (limit_name.empty() || limit_name == "workers_runtime_max")
							workers_runtime_max_ = j.value("workers_runtime_max", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_requests_max")
							workers_requests_max_ = j.value("workers_requests_max", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_label_required")
							workers_label_required_ = j.value("workers_label_required", "unknown");

						if (limit_name.empty() || limit_name == "workers_start_at_once_max")
							workers_start_at_once_max_ = j.value("workers_start_at_once_max", std::int16_t{ 4 });
					}
					else
					{
						if (limit_name.empty() || limit_name == "workers_required")
							workers_required_ += j.value("workers_required", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_min")
							workers_min_ += j.value("workers_min", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_max")
							workers_max_ += j.value("workers_max", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_runtime_max")
							workers_runtime_max_ += j.value("workers_runtime_max", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_requests_max")
							workers_requests_max_ += j.value("workers_requests_max", std::int16_t{ 0 });

						if (limit_name.empty() || limit_name == "workers_label_required")
							workers_label_required_ = j.value("workers_label_required", "unknown");

						if (limit_name.empty() || limit_name == "workers_start_at_once_max")
							workers_start_at_once_max_ += j.value("workers_start_at_once_max", std::int16_t{ 4 });
					}

					if (workers_min_ > workers_max_) workers_min_ = workers_max_;
					if (workers_max_ < workers_min_) workers_max_ = workers_min_;
					if (workers_required_ > workers_max_) workers_required_ = workers_max_;
					if (workers_required_ < workers_min_) workers_required_ = workers_min_;
				}

				void to_json(json& j, output_formating::options options, const std::string& limit_name = "") const
				{
					std::lock_guard<std::mutex> m{ limits_mutex_ };

					if (limit_name.empty() || limit_name == "workers_required")
					{
						j["workers_required"] = workers_required_;
					}
					if (limit_name.empty() || limit_name == "workers_min")
					{
						j["workers_min"] = workers_min_;
					}
					if (limit_name.empty() || limit_name == "workers_max")
					{
						j["workers_max"] = workers_max_;
					}
					if (limit_name.empty() || limit_name == "workers_runtime_max")
					{
						j["workers_runtime_max"] = workers_runtime_max_;
					}
					if (limit_name.empty() || limit_name == "workers_requests_max")
					{
						j["workers_requests_max"] = workers_requests_max_;
					}
					if (limit_name.empty() || limit_name == "workers_start_at_once_max")
					{
						j["workers_start_at_once_max"] = workers_start_at_once_max_;
					}
					if (limit_name.empty() || limit_name == "workers_label_required")
					{
						j["workers_label_required"] = workers_label_required_;
					}

					if (options != output_formating::options::essential)
					{
						if (limit_name.empty() || limit_name == "workers_actual")
						{
							j["workers_actual"] = workers_actual_;
						}
						if (limit_name.empty() || limit_name == "workers_label_actual")
						{
							j["workers_label_actual"] = workers_label_actual_;
						}

						if (limit_name.empty() || limit_name == "workers_pending")
						{
							j["workers_pending"] = workers_pending_;
						}
						if (limit_name.empty() || limit_name == "workers_not_at_label_required")
						{
							j["workers_not_at_label_required"] = workers_not_on_label_required_;
						}
					}
				}

			private:
				std::int16_t workers_pending_{ 0 };
				std::int16_t workers_required_{ 0 };
				std::int16_t workers_actual_{ 0 };
				std::int16_t workers_not_on_label_required_{ 0 };

				std::int16_t workers_min_{ 0 };
				std::int16_t workers_max_{ 0 };

				std::string workers_label_required_{};
				std::string workers_label_actual_{};

				std::int16_t workers_runtime_max_{ 0 };
				std::int16_t workers_requests_max_{ 0 };

				std::int16_t workers_start_at_once_max_{ 4 };
				mutable std::mutex limits_mutex_;
			};

			const limits& workgroups_limits() const { return limits_; }
			limits& workgroups_limits() { return limits_; }

			virtual void direct_workers(
				asio::io_context& io_context,
				const http::configuration& configuration,
				lgr::logger& logger,
				bool workspace_is_updated)
				= 0;

		protected:
			std::string name_;
			std::string workspace_id_;
			std::string type_;
			enum state state_;

			limits limits_;

			container_type workers_;
			mutable mutex_type workers_mutex_;
		};

		class bshell_workgroups : public workgroups
		{

		private:
			std::string bse_;
			std::string bse_bin_;
			std::string bse_user_;
			std::string os_user_;
			std::string os_password_;
			std::string program_;
			std::string cli_options_;
			std::string http_options_;

		public:
			bshell_workgroups(const std::string& workspace_id, const json& worker_type_json)
				: workgroups(workspace_id, worker_type_json["type"])
			{
				from_json(worker_type_json);
			}

			virtual void direct_workers(
				asio::io_context& io_context,
				const http::configuration& configuration,
				lgr::logger& logger,
				bool workspace_is_updated) override
			{
				std::string ec{};
				std::string server_endpoint
					= configuration.get<std::string>("http_this_server_local_url", "http://localhost:4000");

				server_endpoint += "/internal/platform/manager/workspaces";

				std::unique_lock<mutex_type> lock{ workers_mutex_ };

				auto workers_required_to_add = limits_.workers_required_to_add();

				auto workers_label_required = limits_.workers_label_required();
				auto workers_runtime_max = limits_.workers_runtime_max();
				auto workers_requests_max = limits_.workers_requests_max();

				if (workspace_is_updated)
				{
					logger.api(
						"/{s}/{s}/{s} actual: {d}, pending: {d}, required: {d}, min: {d}, max: {d}, label_actual: {s}, "
						"label_required: {s}\n",
						workspace_id_,
						type_,
						name_,
						limits_.workers_actual(),
						limits_.workers_pending(),
						limits_.workers_required(),
						limits_.workers_min(),
						limits_.workers_max(),
						limits_.workers_label_actual(),
						workers_label_required);
				}

				for (std::int16_t n = 0; n < workers_required_to_add; n++)
				{
					std::uint32_t process_id = 0;
					std::string worker_id;
					lock.unlock();
					bool success = create_worker_process(
						server_endpoint, workspace_id_, type_, name_, process_id, worker_id, workers_label_required, ec);

					lock.lock();
					if (state() != workgroups::state::up)
					{
						//assert(false);
						break;
					}

					if (!success) // todo
					{
						logger.api(
							"/{s}/{s}/{s} new worker process ({d}/{d}), failed to start proces: {s}\n",
							workspace_id_,
							type_,
							name_,
							1 + n,
							workers_required_to_add,
							ec);
					}
					else
					{
						logger.api(
							"/{s}/{s}/{s} new worker process ({d}/{d}), processid: {d}, worker_id: {s}\n",
							workspace_id_,
							type_,
							name_,
							1 + n,
							workers_required_to_add,
							static_cast<int>(process_id),
							worker_id);

						workers_.emplace(
							std::pair<const std::string, worker>(worker_id, worker{ worker_id, workers_label_required }));

						limits_.workers_pending_upd(1);
					}
				}

				if (workers_required_to_add < 0)
				{
					for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
					{
						if (worker_it->second.get_base_url().empty()
							|| worker_it->second.get_status() == worker::status::recover)
						{
							++worker_it;
							continue;
						}
						auto& worker = worker_it->second;
						auto worker_label = worker_it->second.worker_label();
						auto worker_runtime = worker_it->second.runtime();
						auto worker_requests = worker_it->second.upstream().responses_tot_.load();

						if ((worker_label != workers_label_required)
							|| ((workers_requests_max > 1) && (worker_requests >= workers_requests_max))
							|| ((workers_runtime_max > 1) && (worker_runtime >= workers_runtime_max))
							|| (worker_it == workers_.begin()))
						{
							http::headers watchdog_headers{ { "Host", "localhost" } };

							std::string base_url = worker_it->second.get_base_url();

							http::client::async_request<http::method::delete_>(
								upstreams_,
								worker_it->second.get_base_url(),
								"/internal/platform/worker/process",
								watchdog_headers,
								std::string{},
								[this, base_url, &logger](http::response_message& response, asio::error_code& error_code) {
									if (!error_code
										&& (response.status() == http::status::ok
											|| response.status() == http::status::no_content
#ifdef LOCAL_TESTING
											|| response.status() == http::status::method_not_allowed // nginx test setup
																										// returns this
#endif //  LOCAL_TESTING
											))
									{
										logger.api(
											"/{s}/{s}/{s}: process deleted for {s}\n",
											workspace_id_,
											type_,
											name_,
											base_url);
									}
									else if (
										error_code
										|| (response.status() != http::status::ok
											&& response.status() != http::status::no_content))
									{
										logger.api(
											"/{s}/{s}/{s}: failed to delete process {s}\n",
											workspace_id_,
											type_,
											name_,
											base_url);
									}

									return;
								});

							worker.set_status(worker::status::drain);
							workers_required_to_add++;

							if (workers_required_to_add == 0)
							{
								break;
							}
						}
						++worker_it;
					}
				}

				//		if (limits_adjustments.contains("limits") == false)
				{
					std::int16_t workers_watchdogs_feeded = 0;
					std::int16_t workers_on_label_required = 0;
					std::int16_t workers_not_on_label_required = 0;
					std::int16_t workers_runtime_max_reached = 0;
					std::int16_t workers_responses_max_reached = 0;

					for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
					{
						if (worker_it->second.get_base_url().empty())
						{
							++worker_it;
							continue;
						}

						auto& worker = worker_it->second;

						auto worker_label = worker_it->second.worker_label();

						if (worker_it->second.get_status() == worker::status::up
							|| worker_it->second.get_status() == worker::status::starting)
						{
							if (worker_label != workers_label_required)
							{
								workers_not_on_label_required++;
							}
							else
							{
								workers_on_label_required++;

								if (worker.upstream().responses_tot_.load() >= workers_requests_max)
								{
									workers_responses_max_reached++;
								}
								else if (worker.runtime() >= workers_runtime_max)
								{
									workers_runtime_max_reached++;
								}
							}

							if (worker_label != limits_.workers_label_actual()) limits_.workers_label_actual(worker_label);
						}

						if (worker_it->second.get_status() == worker::status::recover)
						{
							auto& upstream = upstreams_.add_upstream(
								io_context,
								worker_it->second.get_base_url(),
								"/" + name_ + "/" + type_ + "/" + worker_it->first + "/"
								+ worker_it->second.worker_label());

							worker_it->second.upstream(upstream);

							worker_it->second.set_status(worker::status::up);
						}

						if (worker_it->second.get_status() == worker::status::up)
						{
							auto workers_feed_watchdog = workers_watchdogs_feeded++ < limits_.workers_min();

							http::headers watchdog_headers{
								{ "Host", "localhost" }, { "X-Feed-Watchdog", workers_feed_watchdog ? "true" : "false" }
							};

							http::client::async_request<http::method::post>(
								upstreams_,
								worker_it->second.get_base_url(),
								"/internal/platform/worker/watchdog",
								watchdog_headers,
								std::string{},
								[this, &worker, &logger](http::response_message& response, asio::error_code& error_code) {
									if (!error_code
										&& (response.status() == http::status::ok
											|| response.status() == http::status::no_content)
										&& worker.get_status() != worker::status::up)
									{
										worker.set_status(worker::status::up);
									}
									else if (
										error_code
										|| (response.status() != http::status::ok
											&& response.status() != http::status::no_content))
									{
										worker.set_status(worker::status::drain);

										if (worker.upstream().get_state() != http::async::upstreams::upstream::state::drain
											&& error_code == asio::error::connection_refused)
										{
											logger.api(
												"/{s}/{s}/{s}: failed health check for worker {s}\n",
												workspace_id_,
												type_,
												name_,
												worker.get_base_url());
										}
									}

									return;
								});
						}

						++worker_it;
					}

					auto workers_to_start = workers_not_on_label_required;
					limits_.workers_not_on_label_required(workers_not_on_label_required);

					if (workers_on_label_required + limits_.workers_pending() != limits_.workers_required())
					{
						workers_to_start = workers_not_on_label_required;
					}
					else if (workers_requests_max > 0 && workers_responses_max_reached > 0)
					{
						workers_to_start = workers_responses_max_reached;
					}
					else if (workers_runtime_max_reached > 0 && workers_runtime_max_reached > 0)
					{
						workers_to_start = workers_runtime_max_reached;
					}

					if (workers_to_start > limits_.workers_start_at_once_max())
						workers_to_start = limits_.workers_start_at_once_max();

					for (std::int16_t n = 0; n < workers_to_start; n++)
					{
						std::uint32_t process_id = 0;
						std::string worker_id;
						lock.unlock();
						bool success = create_worker_process(
							server_endpoint,
							workspace_id_,
							type_,
							name_,
							process_id,
							worker_id,
							workers_label_required,
							ec);

						lock.lock();
						if (!success) // todo
						{
							logger.api(
								"/{s}/{s}/{s} new worker process ({d}/{d}), failed to start proces: {s}\n",
								workspace_id_,
								type_,
								name_,
								1 + n,
								workers_required_to_add,
								ec);
						}
						else
						{
							logger.api(
								"/{s}/{s}/{s} new worker process ({d}/{d}), processid: {d}, worker_id: {s}\n",
								workspace_id_,
								type_,
								name_,
								1 + n,
								workers_required_to_add,
								static_cast<int>(process_id),
								worker_id);

							workers_.emplace(std::pair<const std::string, worker>(
								worker_id, worker{ worker_id, workers_label_required }));
						}
					}

					for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
					{
						if (worker_it->second.get_status() == worker::status::drain)
						{
							if (worker_it->second.upstream().connections_busy_.load() == 0)
								worker_it->second.set_status(worker::status::down);
						}

						if (worker_it->second.get_status() == worker::status::down)
						{
							logger.api(
								"/{s}/{s}/{s} delete {s} {s}\n",
								workspace_id_,
								type_,
								name_,
								worker_it->first,
								worker_it->second.get_base_url());

							upstreams_.erase_upstream(worker_it->second.get_base_url());
#ifdef LOCAL_TESTING_WITH_NGINX_BACKEND
							bse_utils::local_testing::_test_sockets.release(
								workspace_id_, worker_it->second.get_base_url());
#endif
							worker_it = workers_.erase(workers_.find(worker_it->first));

							limits_.workers_actual_upd(-1);
						}
						else
							worker_it++;
					}
				}
			};

			void from_json(const json& j) override
			{
				std::unique_lock<mutex_type> g(workers_mutex_);

				workgroups::from_json(j);

				if (j.contains("parameters"))
				{
					try
					{
						bse_ = j["parameters"].value("bse", "");
						bse_bin_ = j["parameters"].value("bse_bin", bse_.empty() ? "" : bse_ + "/bin");
						bse_user_ = j["parameters"].value("bse_user", "");
						os_user_ = j["parameters"].value("os_user", "");
						os_password_ = j["parameters"].value("os_password", "");
						cli_options_ = j["parameters"].value("cli_options", "");
						http_options_ = j["parameters"].value("http_options", "");
						program_ = j["parameters"].value("program", "");
					}
					catch (json::exception&)
					{
					}
				}

				std::int16_t workers_added = 0;

				if (j.contains("workers"))
				{
					for (const auto& worker_json : j["workers"].items())
					{
						auto worker_id = worker_json.value().value("worker_id", "");

						if (worker_id.empty() == false)
						{
							auto id = util::split(worker_id, "_");
							worker_ids_begin(std::atoi(id[1].c_str()));
						}

						auto worker_label = worker_json.value().value("worker_label", "");
						auto process_id = worker_json.value().value("process_id", 1234);
						auto base_url = worker_json.value().value("base_url", "");

#if defined(LOCAL_TESTING_WITH_NGINX_BACKEND)
						if (base_url.empty() == false)
						{
							auto base_url_split = util::split(base_url, ":");
							auto port = std::atoi(base_url_split[2].c_str());

							bse_utils::local_testing::_test_sockets.aquire(workspace_id_, port);
						}
#endif

						auto version = worker_json.value().value("version", "");
						auto status = worker_json.value().value("status", "");

						if (status == "up")
						{
							auto new_worker = workers_.emplace(std::pair<const std::string, worker>(
								worker_id, worker{ worker_id, worker_label, base_url, version, process_id }));

							if (new_worker.second) new_worker.first->second.set_status(worker::status::recover);

							workers_added++;
						}
					}
				}

				limits_.workers_actual_upd(workers_added);
			}

			void from_json(const json& j, const std::string& detail) override
			{
				std::unique_lock<mutex_type> g(workers_mutex_);
				if (detail.empty() || (detail == "bse")) bse_ = j["parameters"].value("bse", "");
				if (detail.empty() || (detail == "bse_bin")) bse_bin_ = j["parameters"].value("bse_bin", "");
				if (detail.empty() || (detail == "bse_user")) bse_user_ = j["parameters"].value("bse_user", "");
				if (detail.empty() || (detail == "os_user")) os_user_ = j["parameters"].value("ose_user", "");
				if (detail.empty() || (detail == "os_password")) os_password_ = j["parameters"].value("os_password", "");
				if (detail.empty() || (detail == "program")) program_ = j["parameters"].value("program", "");
				if (detail.empty() || (detail == "cli_options")) cli_options_ = j["parameters"].value("cli_options", "");
				if (detail.empty() || (detail == "http_options")) http_options_ = j["parameters"].value("http_options", "");
			}

			void to_json(json& j, const std::string& detail) const override
			{
				std14::shared_lock<mutex_type> g(workers_mutex_);

				if (detail.empty() || (detail == "bse")) j["parameters"].emplace("bse", bse_);

				if (detail.empty() || (detail == "bse_user")) j["parameters"].emplace("bse_bin", bse_bin_);

				if (detail.empty() || (detail == "bse_user")) j["parameters"].emplace("bse_user", bse_user_);

				if (detail.empty() || (detail == "os_user")) j["parameters"].emplace("os_user", os_user_);

				if (detail.empty() || (detail == "os_password")) j["parameters"].emplace("os_password", os_password_);

				if (detail.empty() || detail == "program") j["parameters"].emplace("program", program_);

				if (detail.empty() || detail == "cli_options") j["parameters"].emplace("cli_options", cli_options_);

				if (detail.empty() || detail == "http_options") j["parameters"].emplace("http_options", http_options_);
			}

			void to_json(json& j, output_formating::options options) const override
			{
				workgroups::to_json(j, options);

				std14::shared_lock<mutex_type> g(workers_mutex_);
				if (bse_.empty() == false) j["parameters"].emplace("bse", bse_);

				if (bse_bin_.empty() == false) j["parameters"].emplace("bse_bin", bse_bin_);

				if (bse_user_.empty() == false) j["parameters"].emplace("bse_user", bse_user_);

				if (os_user_.empty() == false) j["parameters"].emplace("os_user", os_user_);

				if (os_password_.empty() == false) j["parameters"].emplace("os_password", os_password_);

				j["parameters"].emplace("program", program_);
				j["parameters"].emplace("cli_options", cli_options_);
				j["parameters"].emplace("http_options", http_options_);
			}

			std::atomic<std::uint32_t> worker_ids_{ 0 };

			void worker_ids_begin(std::uint32_t id) { worker_ids_ = worker_ids_.load() <= id ? id + 1 : worker_ids_.load(); }

		public:
			bool create_worker_process(
				const std::string& manager_endpoint,
				const std::string& workspace_id,
				const std::string&,
				const std::string& worker_name,
				std::uint32_t& pid,
				std::string& worker_id,
				const std::string& worker_label,
				std::string& ec) override
			{
				std14::shared_lock<mutex_type> g(workers_mutex_);
				std::stringstream parameters;

				worker_id = "worker_" + std::to_string(worker_ids_++);

				parameters << "-httpserver_options cpm_endpoint:" << manager_endpoint
					<< ",cpm_workgroup_membership_type:worker,cpm_workspace:" << workspace_id
					<< ",cpm_worker_id:" << worker_id << ",cpm_worker_label:" << worker_label
					<< ",cpm_workgroup:" << worker_name;

				if (!http_options_.empty())
					parameters << "," << http_options_ << " ";
				else if (!cli_options_.empty())
					parameters << " ";

				parameters << cli_options_;

				return bse_utils::create_bse_process_as_user(
					bse_,
					bse_bin_,
					"",
					os_user_,
					os_password_,
					bse_bin_ + (bse_bin_ != "" ? "/" : "") + program_ + std::string{ " " } + parameters.str(),
					pid,
					ec);
			}
		};

		class python_workgroups : public workgroups
		{
		private:
			std::string rootdir;

		public:
			python_workgroups(const std::string& workspace_id, const json& worker_type_json)
				: workgroups(workspace_id, "python"), rootdir()
			{
				from_json(worker_type_json);
			}

			virtual ~python_workgroups() {};

			void from_json(const json& j) override
			{
				workgroups::from_json(j);
				json d(j.at("parameters"));
				d.at("python_root").get_to(rootdir);
			}

			void from_json(const json& j, const std::string& detail) override
			{
				if (detail.empty() || detail == "python_root") rootdir = j["parameters"].value("python_root", "");
			};

			void to_json(json& j, const std::string& detail) const override
			{
				if (detail.empty() || detail == "python_root") j["parameters"].emplace("python_root", rootdir);
			}

			void to_json(json& j, output_formating::options options) const override
			{
				workgroups::to_json(j, options);
				j["parameters"].emplace("python_root", rootdir);
			}

			virtual void direct_workers(
				asio::io_context&,
				const http::configuration&,
				lgr::logger&,
				bool) override {};

			virtual bool create_worker_process(
				const std::string&,
				const std::string&, // workspace_id,
				const std::string&, // worker_type,
				const std::string&, // worker_name,
				std::uint32_t&, // pid,
				std::string&,
				const std::string&,
				std::string&) override
			{
				return false;
			};
		};

		class workspace
		{
		public:
			using key_type = std::string;
			using value_type = std::unique_ptr<workgroups>;
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
			workspace(const std::string workspace_id, const json& json_workspace) : workspace_id_(workspace_id), state_(state::up)
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
			std::unique_ptr<workgroups> create_workgroups_from_json(const std::string& type, const json& workgroups_json)
			{
				if (type == "bshells")
					return std::unique_ptr<workgroups>{ new bshell_workgroups{ workspace_id_, workgroups_json } };
				if (type == "ashells")
					return std::unique_ptr<workgroups>{ new bshell_workgroups{ workspace_id_, workgroups_json } };
				if (type == "python-scripts")
					return std::unique_ptr<workgroups>{ new python_workgroups{ workspace_id_, workgroups_json } };
				else
					return nullptr;
			}

		public:
			iterator erase_workgroup(iterator i)
			{
				return workgroups_.erase(i);
			}

			iterator end() { return workgroups_.end(); };
			iterator begin() { return workgroups_.begin(); }
			const_iterator cend() const { return workgroups_.cend(); };
			const_iterator cbegin() const { return workgroups_.cbegin(); }

			bool has_workgroups_available() const
			{
				return workgroups_.empty() == false;
			}

			bool drain_all_workgroups()
			{
				bool result = false;

				for (auto& workgroup : workgroups_)
				{
					if (workgroup.second->state() == workgroups::state::up)
						workgroup.second->state(workgroups::state::drain);
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
							bool found = false;
							if (session.request().get<std::string>(header.name, found, "") == header.value && found == true)
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
								const std::int16_t queue_retry_timeout = 1;
								workgroup.second->workgroups_limits().workers_required_upd(1);

								session.request().set_attribute<std::int16_t>(
									"queued", queue_retry_timeout);
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

			bool add_workgroups(const std::string& name, const std::string& type, json& workgroups_json)
			{
				auto new_workgroups = create_workgroups_from_json(type, workgroups_json);

				if (new_workgroups)
				{
					auto result
						= workgroups_.insert(std::pair<key_type, value_type>(key_type{ name }, std::move(new_workgroups)));

					return result.second;
				}

				return false;
			}

			bool drain_workgroup(const std::string& workgroup_name)
			{
				bool result = false;

				auto workgroup = workgroups_.find(key_type{ workgroup_name });

				if (workgroup != workgroups_.end())
					workgroup->second->state(workgroups::state::drain);

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

					for (auto workgroups = json_workgroups.cbegin(); workgroups != json_workgroups.cend(); workgroups++)
					{
						if (workgroups.value().size())
						{
							auto new_workgroups = create_workgroups_from_json(workgroups.value()["type"], *workgroups);

							if (new_workgroups)
							{
								this->workgroups_[key_type{ workgroups.value()["name"] }]
									= std::move(new_workgroups);
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

			std::atomic<bool>& is_changed() { return is_changed_; }

			mutex_type& workspaces_mutex() { return workspaces_mutex_; }
			const mutex_type& workspaces_mutex() const { return workspaces_mutex_; }


			iterator erase_workspace(iterator i)
			{
				return workspaces_.erase(i);
			}


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

							if (workgroup_state == workgroups::state::drain)
							{
								if ((workgroup->second->workgroups_limits().workers_actual() > 0) || (workgroup->second->workgroups_limits().workers_pending() > 0))
								{
									workgroup->second->drain_all_workers();
								}
								else
								{
									workgroup->second->state(workgroups::state::down);
									workgroup_state = workgroup->second->state();
								}
							}

							if (workgroup_state == workgroups::state::down)
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

					for (auto workspace = workspaces_.begin(); workspace != workspaces_.end(); ++workspace)
					{
						if (workspace->second->state() != workspace::state::up)
							needs_cleanup = true;

						if (workspace->second->has_workgroups_available())
						{
							std14::shared_lock<mutex_type> l2{ workspace->second->workgroups_mutex() };
							for (auto workgroup = workspace->second->begin(); workgroup != workspace->second->end(); ++workgroup)
							{
								if (workgroup->second->state() != workgroups::state::up)
									needs_cleanup = true;

								workgroup->second->direct_workers(io_context, configuration, logger, is_changed());
							}
						}
					}
				}

				auto t1 = std::chrono::steady_clock::now();
				auto elapsed = t1 - t0;

				if (needs_cleanup)
					cleanup_workspaces(logger);

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
							bool found = false;
							if (session.request().get<std::string>(header.name, found, "") == header.value && found == true)
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
					error_message = workspace_id + " does not exits in workspace collection";
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
					is_changed().store(result);
					return result;
				}
				else
				{
					error_message = workspace_id + " does not exits in workspace collection";
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
						if ((workgroup.first == workgroup_name) && (workgroup.second->state() == workgroups::state::up))
							return method(*workgroup.second, error_message);
					}
					error_message = workgroup_name + " does not exists in workgroup collection ";
				}
				else
				{
					error_message = workspace_id + " does not exits in workspace collection";
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
							is_changed().store(result);
							return result;
						}
					}
					error_message = workgroup_name + " does not exits in workgroup collection";
				}
				else
				{
					error_message = workspace_id + " does not exits in workspace collection";
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
						if ((workgroup.first == workgroup_name) && (workgroup.second->state() == workgroups::state::up))
						{
							for (const auto& worker : *(workgroup.second))
							{
								if (worker.first == worker_id) return method(worker.second, error_message);
							}
						}
						error_message = worker_id + " does not exits in workers collection";
					}
					if (error_message.empty()) error_message = workgroup_name + " does not exits in workgroup collection";
				}
				else
				{
					error_message = workspace_id + " does not exits in workspace collection";
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
								if (worker.first == worker_id) return method(worker.second, error_message);
							}
							error_message = worker_id + " does not exits in workers collection";
						}
					}
					if (error_message.empty()) error_message = workgroup_name + " does not exits in workgroup collection";
				}
				else
				{
					error_message = workspace_id + " does not exits in workspace collection";
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

		template <typename S> class manager : public S
		{
		protected:
			using server_base = S;

		private:
			workspaces workspaces_;
			std::thread director_thread_;

			std::string configuration_file_;

		public:
			manager(http::configuration& http_configuration, const std::string& configuration_file)
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
					workspaces_.from_json(json::object());
				}

				server_base::router_.on_get(
					http::server::configuration_.get<std::string>("health_check", "/private/health_check"),
					[this](http::session_handler& session) {
						session.response().assign(http::status::ok, "OK");
						server_base::manager().update_health_check_metrics();
					});

				server_base::router_.on_post("/internal/platform/manager/mirror", [](http::session_handler& session) {
					session.response().status(http::status::ok);
					session.response().type(session.response().get<std::string>("Content-Type", "text/plain"));
					session.response().body() = session.request().body();
					});

				server_base::router_.on_post(
					"/internal/platform/manager/access_log_level", [this](http::session_handler& session) {
						server_base::logger_.set_access_log_level(session.request().body());
						auto new_level = server_base::logger_.current_access_log_level_to_string();
						http::server::configuration_.set("access_log_level", new_level);
						session.response().body() = server_base::logger_.current_access_log_level_to_string();
						session.response().status(http::status::ok);
					});

				server_base::router_.on_get(
					"/internal/platform/manager/access_log_level", [this](http::session_handler& session) {
						session.response().body() = server_base::logger_.current_access_log_level_to_string();
						session.response().status(http::status::ok);
					});

				server_base::router_.on_post(
					"/internal/platform/manager/extended_log_level", [this](http::session_handler& session) {
						server_base::logger_.set_extended_log_level(session.request().body());
						auto new_level = server_base::logger_.current_extended_log_level_to_string();
						http::server::configuration_.set("extended_log_level", new_level);
						session.response().body() = server_base::logger_.current_extended_log_level_to_string();
						session.response().status(http::status::ok);
					});

				server_base::router_.on_get(
					"/internal/platform/manager/extended_log_level", [this](http::session_handler& session) {
						session.response().body() = server_base::logger_.current_extended_log_level_to_string();
						session.response().status(http::status::ok);
					});

				server_base::router_.on_get("/internal/platform/manager/status", [this](http::session_handler& session) {
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
					"/internal/platform/manager/status/{section}", [this](http::session_handler& session) {
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
							std::string version = std::string{ "eln_cpm_" } + get_version_ex(PORT_SET, NULL)
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

				server_base::router_.on_get("/internal/platform/manager/workspaces", [this](http::session_handler& session) {
					json workspaces_json{};
					workspaces_.to_json(workspaces_json);

					json result_json = json::object();
					result_json["workspaces"] = workspaces_json;

					session.response().assign(http::status::ok, result_json.dump(), "application/json");
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}", [this](http::session_handler& session) {
						auto& workspace_id = session.params().get("workspace_id");
						auto error_message = std::string{};

						auto result = workspaces_.select(workspace_id, [&session](workspace& workspace, std::string&) {
							json result_json;
							result_json["workspace"] = workspace;
							session.response().assign(http::status::ok, result_json.dump(), "application/json");
							return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(
									http::status::to_int(session.response().status()), error_message)
								.dump(),
								"application/json");
						}
					});

				server_base::router_.on_post("/internal/platform/manager/workspaces", [this](http::session_handler& session) {
					// Json body: { "id" : <str:workspace_id>, ... }

					try
					{
						json workspace_json = json::parse(session.request().body());

						auto& workspace_id = workspace_json.at("id");

						if (workspaces_.add_workspace(workspace_id, workspace_json) == true)
						{
							session.response().assign(http::status::created);
						}
						else
						{
							session.response().assign(http::status::conflict);
						}
					}
					catch (const json::exception& ex)
					{
						session.response().assign(http::status::bad_request);
						server_base::logger_.error(
							"error when handling on_post for /private/infra/workspaces: {s}\n", ex.what());

						session.response().assign(
							http::status::bad_request,
							error_json(http::status::to_int(session.response().status()), ex.what()),
							"application/json");
					}
					});

				server_base::router_.on_delete(
					"/internal/platform/manager/workspaces/{workspace_id}", [this](http::session_handler& session) {
						auto error_message = std::string{};

						auto& workspace_id = session.params().get("workspace_id");

						auto result = workspaces_.change(
							workspace_id, [&session](workspace& workspace, std::string&) {
								workspace.state(workspace::state::drain);
								session.response().assign(http::status::accepted);
								return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups", [this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");

						auto result = workspaces_.select(workspace_id, [&session](workspace& workspace, std::string&) {
							json result;
							result["workgroups"] = json::array();

							for (auto workgroup = workspace.cbegin(); workgroup != workspace.cend(); ++workgroup)
							{
								json workgroups_json;
								workgroup->second->to_json(workgroups_json, output_formating::options::complete);
								result["workgroups"].emplace_back(workgroups_json);
							}
							session.response().assign(http::status::ok, result.dump(), "application/json");

							return true;
							},
							error_message
								);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(
									http::status::to_int(session.response().status()),
									"workspace_id " + workspace_id + " not found")
								.dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}",
					[this](http::session_handler& session) {
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto error_message = std::string{};

						auto result = workspaces_.select(
							workspace_id, workgroup_name, [&session, workspace_id](const workgroups& workgroups, std::string&) {
								json result_json;
								workgroups.to_json(result_json, output_formating::options::complete);
								session.response().assign(http::status::ok, result_json.dump(), "application/json");
								return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_post(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups", [this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");

						auto result = workspaces_.change(
							workspace_id,
							[&session, workspace_id](workspace& workspace, std::string&) {
								json workgroup_json = json::parse(session.request().body());

								const auto& workgroup_name = workgroup_json.at("name");
								const auto& workgroup_type = workgroup_json.at("type");

								if (workspace.add_workgroups(workgroup_name, workgroup_type, workgroup_json) == true)
								{
									session.response().assign(http::status::created);
								}
								else
								{
									session.response().assign(http::status::conflict);
								}

								return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_delete(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						const auto& workspace_id = session.params().get("workspace_id");
						const auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session, workspace_id, workgroup_name](workgroups& workgroup, std::string&) {

								workgroup.state(workgroups::state::drain);
								session.response().assign(http::status::accepted);
								return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/parameters",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.select(
							workspace_id,
							workgroup_name,
							[&session](const workgroups& workgroup, std::string&) {
								json result_json;
								workgroup.to_json(result_json, std::string{});

								session.response().assign(http::status::ok, result_json.dump(), "application/json");
								return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/parameters/{detail}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};

						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto& detail = session.params().get("detail");

						auto result = workspaces_.select(
							workspace_id,
							workgroup_name,
							[&session, detail](const workgroups& workgroup, std::string&) {
								json result_json;
								workgroup.to_json(result_json, detail);

								session.response().assign(http::status::ok, result_json.dump(), "application/json");
								return true;
							}, error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/workers/{worker_id}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto& worker_id = session.params().get("worker_id");

						auto result
							= workspaces_.select(workspace_id, workgroup_name, worker_id, [&session](const worker& worker, std::string&) {
							json result_json;
							worker.to_json(result_json, output_formating::options::complete);
							session.response().assign(http::status::ok, result_json.dump(), "application/json");
							return true;
								},
								error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/workers",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.select(
							workspace_id,
							workgroup_name,
							[&session](const workgroups& workgroup, std::string&) {
								json result_json;
								json worker_json;

								for (auto workers = workgroup.cbegin(); workers != workgroup.cend(); ++workers)
								{
									workers->second.to_json(worker_json, cloud::platform::output_formating::options::complete);
									result_json.emplace_back(worker_json);
								}

								session.response().assign(http::status::ok, result_json.dump(), "application/json");
								return true;
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_post(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/workers",
					[this](http::session_handler& session) {
						auto error_message = std::string{};

						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session, this](workgroups& workgroup, std::string&) {

								json worker_json = json::parse(session.request().body());
								const std::string& worker_label = worker_json["worker_label"];
								const std::string& worker_id = worker_json["worker_id"];

								auto result = workgroup.add_worker(worker_id, worker_label, worker_json, server_base::get_io_context());

								if (result)
									session.response().assign(http::status::no_content);
								else
									session.response().assign(http::status::conflict);

								return true;
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_delete(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/workers/{worker_id}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto& worker_id = session.params().get("worker_id");

						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session, worker_id](workgroups& workgroup, std::string&) {

								auto result = workgroup.delete_worker(worker_id);

								if (result)
									session.response().assign(http::status::no_content);

								return result;
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_delete(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/workers/{worker_id}/process",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto& worker_id = session.params().get("worker_id");

						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session, worker_id](workgroups& workgroup, std::string&) {

								auto result = workgroup.delete_worker_process(worker_id);

								if (result) session.response().assign(http::status::no_content);

								return result;
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/limits",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.select(
							workspace_id,
							workgroup_name,
							[&session](const workgroups& workgroup, std::string&) {
								json result_json;
								json limits_json;
								workgroup.workgroups_limits().to_json(limits_json, output_formating::options::complete);

								result_json["limits"] = limits_json;

								session.response().assign(http::status::ok, result_json.dump(), "application/json");
								return true;
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/limits/{limit_name}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.select(
							workspace_id,
							workgroup_name,
							[&session](const workgroups& workgroup, std::string&) {
								json result_json;
								json limits_json;

								auto& limit_name = session.params().get("limit_name");

								workgroup.workgroups_limits().to_json(limits_json, output_formating::options::complete, limit_name);

								result_json["limits"] = limits_json;

								session.response().assign(http::status::ok, result_json.dump(), "application/json");
								return true;
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_put(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/limits",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");

						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session](workgroups& workgroup, std::string&) {

								json result_json;
								try
								{
									json limits_json = json::parse(session.request().body());
									workgroup.workgroups_limits().from_json(limits_json["limits"]);
									session.response().assign(http::status::no_content);
									result_json["limits"] = limits_json;
									session.response().assign(http::status::ok, result_json.dump(), "application/json");
									return true;

								}
								catch (json::exception&)
								{
									// TODO error response handling
									return false;
								}

							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}

					});

				server_base::router_.on_put(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/limits/{limit_name}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto& limit_name = session.params().get("limit_name");


						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session, &limit_name](workgroups& workgroup, std::string&) {
								try
								{
									json limits_json = json::parse(session.request().body());
									json result_json;

									workgroup.workgroups_limits().from_json(limits_json, limit_name, workgroups::limits::from_json_operation::set);

									workgroup.workgroups_limits().to_json(
										result_json, output_formating::options::complete, limit_name);

									session.response().assign(http::status::ok, result_json.dump(), "application/json");
									return true;
								}
								catch (json::exception&)
								{
									// TODO error response handling
									return false;
								}
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}

					});

				server_base::router_.on_patch(
					"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{workgroup_name}/limits/{limit_name}",
					[this](http::session_handler& session) {
						auto error_message = std::string{};
						auto& workspace_id = session.params().get("workspace_id");
						auto& workgroup_name = session.params().get("workgroup_name");
						auto& limit_name = session.params().get("limit_name");


						auto result = workspaces_.change(
							workspace_id,
							workgroup_name,
							[&session, &limit_name](workgroups& workgroup, std::string&) {
								try
								{
									json limits_json = json::parse(session.request().body());
									json result_json;

									workgroup.workgroups_limits().from_json(limits_json, limit_name, workgroups::limits::from_json_operation::add);

									workgroup.workgroups_limits().to_json(
										result_json, output_formating::options::complete, limit_name);

									session.response().assign(http::status::ok, result_json.dump(), "application/json");
									return true;
								}
								catch (json::exception&)
								{
									// TODO error response handling
									return false;
								}
							},
							error_message);

						if (result == false)
						{
							session.response().assign(
								http::status::not_found,
								error_json(http::status::to_int(session.response().status()), error_message).dump(),
								"application/json");
						}
					});

				server_base::router_.on_get("/internal/platform/manager/upstreams", [this](http::session_handler& session) {
					auto include_connections = session.request().query().get<bool>("connections", false);
					const auto& format = session.request().get<std::string>("Accept", "application/text");

					if (format.find("application/json") != std::string::npos)
					{
						json result = json::array();
						for (const auto& workspace : workspaces_)
						{
							for (const auto& workgroup : *workspace.second)
							{
								json upstream_json = json::object();

								workgroup.second->upstreams_.to_json(
									workspace.first, http::async::upstreams::options::upstreams_only, upstream_json);

								result.emplace_back(upstream_json);
							}
						}
						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
						for (const auto& workspace : workspaces_)
						{
							std::stringstream ss;
							for (const auto& workgroup : *workspace.second)
							{
								ss.str(std::string());
								if (include_connections)
									ss << workgroup.second->upstreams_.to_string(
										workspace.first, http::async::upstreams::options::include_connections);
								else
									ss << workgroup.second->upstreams_.to_string(
										workspace.first, http::async::upstreams::options::upstreams_only);

								session.response().body() += ss.str();
							}
						}
						session.response().type("text");
						session.response().status(http::status::ok);
					}
					});

				server_base::router_.on_proxy_pass("/", [this](http::session_handler& session) {
					session.response().status(http::status::service_unavailable);
					workspaces_.proxy_pass(session);
					});

				server_base::router_.on_internal_error([this](http::session_handler& session, std::exception& e) {
					server_base::logger().info(
						"api-error with requested url: \"{s}\", error: \"{s}\", and request body:\n \"{s}\"",
						session.request().url_requested(),
						e.what(),
						http::to_string(session.request()));

					session.response().assign(http::status::internal_server_error, e.what());
					});
			}

			virtual ~manager() {}

			http::server::state start() override
			{
				try
				{
					auto ret = server_base::start();
					director_thread_ = std::thread{ [this]() { director_handler(); } };

					return ret;
				}
				catch (std::runtime_error& e)
				{
					std::cerr << e.what() << std::endl;
					_exit(-1);
				}
			}

			enum class json_options
			{
				complete,
				essential
			};

			void to_json(json& j, output_formating::options options = output_formating::options::complete) const
			{
				json workspaces_json;
				workspaces_.to_json(workspaces_json, options);

				j["workspaces"] = workspaces_json;
			}

			void from_json(json&) const {}

		private:
			void director_handler()
			{
				while (!server_base::is_active() && !server_base::is_activating())
				{
					std::this_thread::sleep_for(std::chrono::seconds(1));
				}

				while (server_base::is_active() || server_base::is_activating())
				{
					if (server_base::is_active())
					{
						workspaces_.direct_workspaces(
							server_base::get_io_context(), server_base::configuration_, server_base::logger_);

						if (workspaces_.is_changed())
						{
							json manager_json = json::object();
							to_json(manager_json, output_formating::options::essential);
							std::ifstream prev_configuration_file{ configuration_file_, std::ios::binary };
							std::ofstream bak_config_file{ configuration_file_ + ".bak", std::ios::binary };

							bak_config_file << prev_configuration_file.rdbuf();
							prev_configuration_file.close();

							std::ofstream new_config_file{ configuration_file_ };

							new_config_file << std::setw(4) << manager_json;

							if (new_config_file.fail() == false)
								server_base::logger_.api("config saved to: \"{s}\"\n", configuration_file_);

							workspaces_.is_changed().store(false);
						}
					}

					std::this_thread::sleep_for(std::chrono::seconds(1));
				}
			}

		public:
			static json error_json(const int code, const std::string& message)
			{
				json error_json;
				error_json["error"].emplace_back(json{ { "code", code }, { "message", message } });

				return error_json;
			}
		};

		static std::unique_ptr<manager<http::async::server>> eln_cpm_server_;

	} // namespace platform
} // namespace cloud

inline bool start_eln_cpm_server(std::string config_file, std::string config_options, bool run_as_daemon, bool run_selftests)
{
	std::string server_version = std::string{ "eln_cpm" };

	if (run_as_daemon) util::daemonize("/tmp", "/var/lock/" + server_version + ".pid");

	http::configuration http_configuration{
		{ { "server", server_version },
		  { "http_listen_port_begin", "4000" },
		  { "private_base", "/internal/platform/manager" },
		  { "health_check", "/internal/platform/manager/healthcheck" },
		  { "private_ip_white_list", "::/0" },
		  { "public_ip_white_list", "::/0" },
		  { "access_log_level", "access_log" },
		  { "access_log_file", "access_log.txt" },
		  { "extended_log_level", "api" },
		  { "extended_log_file", "console" },
		  { "https_enabled", "false" },
		  { "http_enabled", "true" },
		  { "http_use_portsharding", "false" } },
		config_options
	};

	if (run_selftests)
	{
		config_file = "selftest-" + std::to_string(getpid()) + ".json";
	}

	cloud::platform::eln_cpm_server_ = std::unique_ptr<cloud::platform::manager<http::async::server>>(
		new cloud::platform::manager<http::async::server>(http_configuration, config_file));

	auto result = cloud::platform::eln_cpm_server_->start() == http::server::state::active;

	if (run_selftests)
		result = tests::run();

	return result;
}

inline bool start_eln_cpm_server(int argc, const char** argv)
{
	prog_args::arguments_t cmd_args(
		argc,
		argv,
		{ { "config",
			{ prog_args::arg_t::arg_val, " <config>: filename for the workspace config file or url", "config.json" } },
		  { "options", { prog_args::arg_t::arg_val, "<options>: see doc.", "" } },
		  { "daemonize", { prog_args::arg_t::flag, "run daemonized" } },
		  { "httpserver_options", { prog_args::arg_t::arg_val, "<options>: see doc.", "" } },
		  { "selftests", { prog_args::arg_t::flag, "run selftests" } },
		{ "selftests_worker", { prog_args::arg_t::flag, "false" } } }
	);

	if (cmd_args.process_args() == false)
	{
		std::cout << "error in arguments \n";
		exit(1);
	}

	if (cmd_args.get_val("selftests_worker") == "")
		return start_eln_cpm_server(
			cmd_args.get_val("config"),
			cmd_args.get_val("options"),
			cmd_args.get_val("daemonize") == "true",
			cmd_args.get_val("selftests") == "true");
	else
	{
		tests::start_cld_wrk_server(
			cmd_args.get_val("httpserver_options"),
			cmd_args.get_val("daemonize") == "true");

		tests::run_cld_wrk_server();
		tests::stop_cld_wrk_server();

		exit(0);
	}
}

inline void run_eln_cpm_server()
{
	while (cloud::platform::eln_cpm_server_->is_active())
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

inline int stop_eln_cpm_server()
{
	cloud::platform::eln_cpm_server_->stop();
	cloud::platform::eln_cpm_server_.release();

	return 0;
}
