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
	upstream_controller_base(const http::basic::server& server) : server_(server) {}

	virtual ~upstream_controller_base(){};

	virtual result add() const noexcept = 0;

	virtual result remove() const noexcept = 0;

protected:
	const http::basic::server& server_;
};

namespace implementations
{

class upstream_controller_nginx : public upstream_controller_base
{
public:
	upstream_controller_nginx(const http::basic::server& server) : upstream_controller_base(server)
	{
		endpoint_base_url_ = server.config().get<std::string>("upstream_node_nginx_endpoint", "http://localhost:7777") + "/"
							 + server.config().get<std::string>("upstream_node_nginx_group",  "bshell-workers")
							 + "?upstream=" + server.config().get<std::string>("upstream_node_nginx_group", "bshell-workers") + "-zone";
	};

	result add() const noexcept
	{
		do
		{
			bool retry = false;
			auto up_result = http::client::request<http::method::get>(
				endpoint_base_url_
					+ "&up=&server=" + server_.config().get<std::string>("upstream_node_this_ip", "127.0.0.1")
					+ ":" + server_.config().get("http_listen_port"),
				{},
				{});

			if (up_result.status() == http::status::ok)
			{
				return http::upstream::sucess;
			}
			else
			{
				auto add_result = http::client::request<http::method::get>(
					endpoint_base_url_ + "&add=&server="
						+ server_.config().get<std::string>("upstream_node_this_ip", "127.0.0.1") + ":"
						+ server_.config().get("http_listen_port"),
					{},
					{});

				if (add_result.status() == http::status::ok)
				{
					return http::upstream::sucess;
				}
				else
				{
					if (retry == true) break;

					retry = true;
				}
			}
		} while (remove() == http::upstream::sucess); // remove ourself and try again....

		return http::upstream::failed;
	}

	result remove() const noexcept
	{
		auto down_result = http::client::request<http::method::get>(
			endpoint_base_url_
				+ "&down=&server=" + server_.config().get<std::string>("upstream_node_this_ip", "127.0.0.1")
				+ ":" + server_.config().get("http_listen_port"),
			{},
			{});

		if (down_result.status() == http::status::ok)
		{
			auto remove_result = http::client::request<http::method::get>(
				endpoint_base_url_ + "&remove=&server="
					+ server_.config().get<std::string>("upstream_node_this_ip", "127.0.0.1") + ":"
					+ server_.config().get("http_listen_port"),
				{},
				{});
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
	upstream_controller_haproxy(const http::basic::server& server) : upstream_controller_base(server) {}

	result add() const noexcept
	{
		result ret = http::upstream::failed;
		char buffer[4096];

		auto http_listen_port = server_.config().get<std::string>("http_listen_port");

		auto haproxy_addr = network::ip::make_address(
			server_.config().get<std::string>("upstream_node_haproxy_endpoint", "::1:9999"));

		auto this_addr = network::ip::make_address(
			server_.config().get<std::string>("upstream_node_this_ip", "127.0.0.1") + ":" + http_listen_port);

		auto backend = server_.config().get<std::string>("upstream_node_haproxy_backend", "upstream");
		auto node = server_.config().get<std::string>("upstream_node_haproxy_node", "bshell-0");

		network::tcp::v6 s(haproxy_addr);
		network::error_code ec;

		s.connect(ec);

		if (!ec)
		{
			auto cmd = "set server " + backend + "/" + node + " addr " + this_addr.first + " port " + http_listen_port
					   + "\n";

			network::write(s.socket(), cmd);

			network::read(s.socket(), network::buffer(buffer, sizeof(buffer))); // on error no such server // success:
																				// no need to change

			s.close();
			s.connect(ec);

			if (!ec)
			{
				cmd = "enable server " + backend + "/" + node + " state ready\n";

				network::write(s.socket(), cmd);
				network::read(s.socket(), network::buffer(buffer, sizeof(buffer)));

				ret = http::upstream::sucess;
			}
		}

		return ret;
	}

	result remove() const noexcept
	{
		result ret = http::upstream::failed;
		char buffer[4096];

		auto http_listen_port = server_.config().get<std::string>("http_listen_port");

		auto haproxy_addr = network::ip::make_address(
			server_.config().get<std::string>("upstream_node_haproxy_endpoint", "::1:9999"));

		auto this_addr = network::ip::make_address(
			server_.config().get<std::string>("upstream_node_haproxy_this_ip", "127.0.0.1") + ":" + http_listen_port);

		auto backend = server_.config().get<std::string>("upstream_node_haproxy_backend", "upstream");
		auto node = server_.config().get<std::string>("upstream_node_haproxy_node", "bshell-0");

		network::tcp::v6 s(haproxy_addr);
		network::error_code ec;

		s.connect(ec);

		if (!ec)
		{
			auto cmd = "set server " + backend + "/" + node + " state drain\n";

			network::write(s.socket(), cmd);
			network::read(s.socket(), network::buffer(buffer, sizeof(buffer)));
			ret = http::upstream::sucess;
		}

		return ret;
	}

private:
	//	network::tcp::endpoint& nginx_endpoint_;
};

} // namespace implementations

std::unique_ptr<upstream_controller_base> make_upstream_controler_from_configuration(const http::basic::server& server);

class enable_server_as_upstream
{
public:
	enable_server_as_upstream(const http::basic::server* server)
		: server_(*server), upstream_controller_(make_upstream_controler_from_configuration(*server)){};

private:
	const http::basic::server& server_;

protected:
	std::unique_ptr<upstream_controller_base> upstream_controller_;
};

std::unique_ptr<upstream_controller_base> make_upstream_controler_from_configuration(const http::basic::server& server)
{
	if (server.config().get("upstream_node_type") == "nginx")
	{
		return std::move(std::unique_ptr<http::upstream::implementations::upstream_controller_nginx>(
			new http::upstream::implementations::upstream_controller_nginx(server)));
	}
	else if (server.config().get("upstream_node_type") == "haproxy")
	{
		return std::move(std::unique_ptr<http::upstream::implementations::upstream_controller_haproxy>(
			new http::upstream::implementations::upstream_controller_haproxy(server)));
	}

	return {};
}

} // namespace upstream

} // namespace http
