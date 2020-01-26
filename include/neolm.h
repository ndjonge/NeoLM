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

template <class S> class license_manager
{
public:
private:
	// /private/infra/implementer/version
	// /private/infra/implementer/status
	// /private/infra/implementer/status{1}
	// /private/infra/implementer/healthcheck
	// /private/infra/implementer/shutdown

	class api_server : public S, public http::upstream::enable_server_as_upstream
	{
	public:
		api_server(license_manager& license_manager, http::configuration& configuration)
			: S(configuration), http::upstream::enable_server_as_upstream(this), license_manager_(license_manager)
		{
			S::router_.on_post(
				S::configuration_.template get<std::string>("internal_base", "") + "/log_level",
				[this](http::session_handler& session) {
					logger_.set_level(session.request().body());
					auto new_level = logger_.current_level_to_string();

					session.response().body() = logger_.current_level_to_string();
					http::basic::server::configuration_.set("log_level", new_level);

					session.response().status(http::status::ok);
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

	void stop_server() { this->api_server_.deactivate(); }

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

		while (api_server_.is_active())
		{
			api_server_.logger_.info("Alive!\n");
			std::this_thread::sleep_for(std::chrono::seconds(10));
		}
	}

private:
	http::configuration configuration_;
	api_server api_server_;
	std::string home_dir_;

}; // namespace neolm

} // namespace neolm
