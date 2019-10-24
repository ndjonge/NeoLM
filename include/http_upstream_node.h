#pragma once

#include <memory>
#include <string>

#include "http_basic.h"

namespace http
{

namespace upstream
{
enum result
{
	failed,
	sucess
};

class upstream_controller_base
{
public:
	upstream_controller_base(http::configuration& configuration, http::basic::server& server)
		: configuration_(configuration)
		, server_(server)
	{
	}

	virtual ~upstream_controller_base(){};

	virtual result add() const noexcept = 0;

	virtual result remove() const noexcept = 0;

protected:
	http::configuration& configuration_;
	http::basic::server& server_;
};

namespace implementations
{

class upstream_controller_nginx : public upstream_controller_base
{
public:
	upstream_controller_nginx(http::configuration& configuration, http::basic::server& server)
		: upstream_controller_base(configuration, server)
	{
		endpoint_base_url_
			= configuration_.get("upstream-node-nginx-endpoint") + "/" + configuration_.get("upstream-node-nginx-group") + "?upstream=" + configuration_.get("upstream-node-nginx-group") + "-zone";
	};

	result add() const noexcept
	{
		do
		{
			auto up_result = http::basic::client::get(
				endpoint_base_url_ + "&up=&server=" + configuration_.get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":" + configuration_.get("http_listen_port"), {}, {});

			if (up_result.status() == http::status::ok)
			{
				return http::upstream::sucess;
			}
			else
			{
				auto add_result = http::basic::client::get(
					endpoint_base_url_ + "&add=&server=" + configuration_.get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":" + configuration_.get("http_listen_port"), {}, {});

				return http::upstream::sucess;
			}
		} while (remove() == http::upstream::sucess); // remove ourself and try again....

		return http::upstream::failed;
	}

	result remove() const noexcept
	{
		auto down_result = http::basic::client::get(
			endpoint_base_url_ + "&down=&server=" + configuration_.get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":" + configuration_.get("http_listen_port"), {}, {});

		if (down_result.status() == http::status::ok)
		{
			auto remove_result = http::basic::client::get(
				endpoint_base_url_ + "&remove=&server=" + configuration_.get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":" + configuration_.get("http_listen_port"), {}, {});
			return http::upstream::sucess;
		}
		else
			return http::upstream::failed;
	}

private:
	std::string endpoint_base_url_;
	std::string my_endpoint_;
};

class upstream_controller_haproxy : public upstream_controller_base
{
public:
	upstream_controller_haproxy(http::configuration& configuration, http::basic::server& server)
		: upstream_controller_base(configuration, server)
	{
	}

	result add() const noexcept { return http::upstream::sucess; }

	result remove() const noexcept { return http::upstream::sucess; }

private:
	//	network::tcp::endpoint& nginx_endpoint_;
};

} // namespace implementations

std::unique_ptr<class upstream_controller_base> make_upstream_controler_from_configuration(http::configuration& configuration, http::basic::server& server);

class enable_server_as_upstream
{
public:
	enable_server_as_upstream(http::configuration& configuration, http::basic::server& server)
		: configuration_(configuration)
		, server_(server)
		, upstream_controller_(make_upstream_controler_from_configuration(configuration, server)){};

private:
	http::configuration& configuration_;
	http::basic::server& server_;

protected:
	std::unique_ptr<upstream_controller_base> upstream_controller_;
};

std::unique_ptr<upstream_controller_base> make_upstream_controler_from_configuration(http::configuration& configuration, http::basic::server& server)
{
	if (configuration.get("upstream-node-type") == "nginx")
	{
		return std::unique_ptr<upstream_controller_base>(new http::upstream::implementations::upstream_controller_nginx(configuration, server));
	}
	else if (configuration.get("upstream-node-type") == "haproxy")
	{
		return std::unique_ptr<upstream_controller_base>(new http::upstream::implementations::upstream_controller_haproxy(configuration, server));
	}

	return {};
}

} // namespace upstream

} // namespace http
