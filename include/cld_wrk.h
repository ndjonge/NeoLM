#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>

// wireshark:
// portrange 8000-8032 or port 4000

#define CURL_STATICLIB

#ifdef USE_VCPKG_INCLUDES
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
#include "cld_worker_instance.h"

using json = nlohmann::json;

namespace cloud
{
namespace platform
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

} // namespace platform
} // namespace cloud

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
		  { "extended_log_level", "api" },
		  { "extended_log_file", "console" },
		  { "https_enabled", "false" },
		  { "http_enabled", "true" },
		  { "http_use_portsharding", "false" } },
		config_options
	};

	cloud::platform::cld_wrk_server_ = std::unique_ptr<cloud::platform::worker<http::sync::server>>(
		new cloud::platform::worker<http::sync::server>(http_configuration));

	auto result  = cloud::platform::cld_wrk_server_->start() == http::server::state::active;

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
	while (cloud::platform::cld_wrk_server_->is_active())
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

inline int stop_cld_wrk_server()
{
	cloud::platform::cld_wrk_server_->stop();
	cloud::platform::cld_wrk_server_.release();
	return 0;
}
