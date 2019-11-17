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
	upstream_controller_base(const http::basic::server& server)
		: server_(server)
	{
	}

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
	upstream_controller_nginx(const http::basic::server& server)
		: upstream_controller_base(server)
	{
		endpoint_base_url_ = server.configuration().get("upstream-node-nginx-endpoint") + "/"
							 + server.configuration().get("upstream-node-nginx-group")
							 + "?upstream=" + server.configuration().get("upstream-node-nginx-group") + "-zone";
	};

	result add() const noexcept
	{
		do
		{
			auto up_result = http::client::request<http::method::get>(
				endpoint_base_url_ + "&up=&server="
					+ server_.configuration().get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":"
					+ server_.configuration().get("http_listen_port"),
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
						+ server_.configuration().get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":"
						+ server_.configuration().get("http_listen_port"),
					{},
					{});

				return http::upstream::sucess;
			}
		} while (remove() == http::upstream::sucess); // remove ourself and try again....

		return http::upstream::failed;
	}

	result remove() const noexcept
	{
		auto down_result = http::client::request<http::method::get>(
			endpoint_base_url_ + "&down=&server="
				+ server_.configuration().get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":"
				+ server_.configuration().get("http_listen_port"),
			{},
			{});

		if (down_result.status() == http::status::ok)
		{
			auto remove_result = http::client::request<http::method::get>(
				endpoint_base_url_ + "&remove=&server="
					+ server_.configuration().get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":"
					+ server_.configuration().get("http_listen_port"),
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
	upstream_controller_haproxy(const http::basic::server& server)
		: upstream_controller_base(server)
	{
	}

	result add() const noexcept 
	{ 
		char buffer[4096];

		auto haproxy_addr = network::ip::make_address("upstream-node-haproxy-endpoint");
		auto this_addr = network::ip::make_address(
			server_.configuration().get<std::string>("upstream-node-nginx-my-endpoint", "127.0.0.1") + ":"
			+ server_.configuration().get("http_listen_port"));

		network::tcp::v6 s(haproxy_addr);
		network::error_code ec;

		s.connect(ec);

		if (!ec)
		{
			std::cout << "set server " + server_.configuration().get("upstream-node-haproxy-group") + "/" + +" addr "
							 + this_addr.first + " port " + std::to_string(this_addr.second) + "\n";

			network::write(
				s.socket(),
				"set server " + server_.configuration().get("upstream-node-haproxy-group") + "/" + +" addr "
					+ this_addr.first
					+ " port " + std::to_string(this_addr.second) + "\n");

			network::read(s.socket(), network::buffer(buffer, sizeof(buffer)));
		}

		s.close();
		s.connect(ec);

		if (!ec)
		{

			std::cout << "enable server " + server_.configuration().get("upstream-node-haproxy-group") + "/"
							 + this_addr.first
							 + " state ready\n";

			network::write(
				s.socket(),
				"enable server " + server_.configuration().get("upstream-node-haproxy-group") + "/" + this_addr.first
					+ " state ready\n");
			network::read(s.socket(), network::buffer(buffer, sizeof(buffer)));
		}


		return http::upstream::sucess; 
	}

	result remove() const noexcept 
	{ 
		//char buffer[4096];

		//network::tcp::v6 s;
		//

		//network::ip::address reverse_proxy_this_node_url_address
		//	= network::ip::make_address(reverse_proxy_this_node_url);

		//network::error_code ec;

		//s.connect(ec);

		//if (!ec)
		//{
		//	std::cout << "set server " + upstream_node_name + " state drain\n";
		//	network::write(s.socket(), "set server " + upstream_node_name + " state drain\n");
		//	network::read(s.socket(), network::buffer(buffer, sizeof(buffer)));
		//}

		return http::upstream::sucess; 
	}

private:
	//	network::tcp::endpoint& nginx_endpoint_;
};

} // namespace implementations

std::unique_ptr<upstream_controller_base> make_upstream_controler_from_configuration(const http::basic::server& server);

class enable_server_as_upstream
{
public:
	enable_server_as_upstream(const http::basic::server* server) : server_(*server), upstream_controller_(
		make_upstream_controler_from_configuration(*server)
	){};


private:
	const http::basic::server& server_;

protected:
	mutable std::unique_ptr<upstream_controller_base> upstream_controller_; 
};

std::unique_ptr<upstream_controller_base>
make_upstream_controler_from_configuration(const http::basic::server& server)
{
	if (server.configuration().get("upstream-node-type") == "nginx")
	{
		return std::move(std::unique_ptr<http::upstream::implementations::upstream_controller_nginx>(
			new http::upstream::implementations::upstream_controller_nginx(server)));
	}
	else if (server.configuration().get("upstream-node-type") == "haproxy")
	{
		return std::move(std::unique_ptr<http::upstream::implementations::upstream_controller_haproxy>(
			new http::upstream::implementations::upstream_controller_haproxy(server)));
	}

	return {};
}

} // namespace upstream

} // namespace http
