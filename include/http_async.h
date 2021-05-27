#pragma once

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <deque>
#include <thread>

#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4459) // asio / VC2019 issue, disable warning C4459 : Declaration of "query" shadows global
// declaration
#endif


#ifdef USE_WOLFSSL
#include "infor_ssl.h"
#ifndef ASIO_USE_WOLFSSL
#define ASIO_USE_WOLFSSL
#endif

#ifdef WIN32
#undef _POSIX_THREADS
#endif

#endif

#include <asio.hpp>
#include <asio/ssl.hpp>

#if defined(WIN32)
#pragma warning(pop)
#endif
#include "http_basic.h"

namespace util
{

inline std::string fully_qualified_hostname()
{
	std::array<char, 256> hostname_buffer;
	::gethostname(&hostname_buffer[0], sizeof(hostname_buffer));

	asio::ip::tcp::resolver::query q(hostname_buffer.data(), "80", asio::ip::tcp::resolver::query::canonical_name);

	asio::error_code ec;
	asio::io_service io_service;
	asio::ip::tcp::resolver resolver(io_service);

	auto hostnames = resolver.resolve(q, ec);
	std::string result;

	if (!ec)
	{
		result = std::string{ hostname_buffer.data() };
		for (auto hostname : hostnames)
		{
			result = hostname.host_name();
		}
	}
	else
	{
		result = std::string{ hostname_buffer.data() };
	}

	std::transform(
		result.begin(), result.end(), result.begin(), [](char c) { return static_cast<char>(std::tolower(c)); });

	return result;
}
} // namespace util

namespace http
{

namespace async
{

inline std::size_t get_static_id() noexcept
{
	static std::atomic<std::size_t> id{ 0 };
	return id++;
}

class upstreams
{
public:
	template <typename upstream_type> class connection
	{
	public:
		enum class state
		{
			waiting,
			idle,
			error,
			drain
		};

		std::string to_string(state s)
		{
			switch (s)
			{
				case state::waiting:
					return "waiting";
				case state::idle:
					return "idle";
				case state::drain:
					return "drain";
				case state::error:
					return "error";
				default:
					return "?";
			}
		}

		connection(asio::io_context& io_context, const std::string& host, std::string port, upstream_type& owner)
			: host_(host)
			, port_(port)
			, id_(owner.id() + "-" + port_)
			, resolver_(io_context)
			, socket_(io_context)
			, owner_(owner)
		{
			asio::error_code error_code;
		};

		connection(const connection& s) = delete;
		connection(connection&& s) = delete;

		connection& operator=(const connection& s) = delete;
		connection& operator=(connection&& s) = delete;

		bool should_drain() const
		{
			return owner_.state_ == upstreams::upstream::state::drain || state_ == state::error;
		}

		void release()
		{
			--(owner_.connections_busy_);
			if (state_ != state::drain)
				state_ = state::idle;
			//owner_.set_state(upstream::state::up);
		}

		void drain()
		{
			--(owner_.connections_busy_);
			state_ = state::drain;
		}

		void error()
		{
			--(owner_.connections_busy_);
			state_ = state::error;
		}

		bool is_removable() { return state_ == state::drain || state_ == state::error; }

		const std::string& id() const { return id_; }

		void to_string(std::ostringstream& ss)
		{
			ss << "  +--> " << id_ << " " << to_string(state_) << " "
			   << static_cast<std::uint16_t>(socket_.lowest_layer().native_handle()) << "\n";
		}

		asio::ip::tcp::socket& socket() { return socket_; }
		std::atomic<state>& get_state() { return state_; }

		std::string host_;
		std::string port_;
		std::string id_;
		std::vector<char> buffer_;
		asio::ip::tcp::resolver resolver_;

		upstream_type& owner() { return owner_; }

	private:
		std::atomic<connection::state> state_{ state::idle };
		asio::ip::tcp::socket socket_;
		upstream_type& owner_;
	};

	void up(const std::string& base_url)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };

		auto upstream_to_change_state
			= std::find_if(upstreams_.cbegin(), upstreams_.cend(), [base_url](const std::unique_ptr<upstream>& rhs) {
				  return (rhs->base_url_ == base_url);
			  });

		if (upstream_to_change_state != upstreams_.cend())
		{
			upstream_to_change_state->get()->set_state(http::async::upstreams::upstream::state::up);
		}
	}

	void drain(const std::string& base_url)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };

		auto upstream_to_change_state
			= std::find_if(upstreams_.cbegin(), upstreams_.cend(), [base_url](const std::unique_ptr<upstream>& rhs) {
				  return (rhs->base_url_ == base_url);
			  });

		if (upstream_to_change_state != upstreams_.cend())
		{
			upstream_to_change_state->get()->set_state(http::async::upstreams::upstream::state::drain);
		}
	}

	void down(const std::string& base_url)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };

		auto upstream_to_change_state
			= std::find_if(upstreams_.cbegin(), upstreams_.cend(), [base_url](const std::unique_ptr<upstream>& rhs) {
				  return (rhs->base_url_ == base_url);
			  });

		if (upstream_to_change_state != upstreams_.cend())
		{
			while (upstream_to_change_state->get()->connections_busy_ > 0)
			{
				std::this_thread::yield();
			}
			upstream_to_change_state->get()->set_state(http::async::upstreams::upstream::state::down);
		}
	}

	enum options
	{
		upstreams_only,
		include_connections
	};

	void to_json(const std::string& workspace_id, options options, json& result)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };

		result = json::array();

		for (auto& upstream : upstreams_)
		{
			json upstream_json = json::object();
			auto connections_busy_ = upstream->connections_busy_.load();
			auto connections_total = upstream->connections_total_.load();
			auto connections_idle = connections_total - connections_busy_;
			auto upstream_state = "up";

			if (upstream->state_ == upstream::state::drain)
				upstream_state = "drain";
			else if (upstream->state_ == upstream::state::down)
				upstream_state = "down";

			upstream_json["base_url"] = upstream->base_url_;
			upstream_json["workspace_id"] = workspace_id;
			upstream_json["state"] = upstream_state;

			upstream_json["connections"]["total"] = connections_total;
			upstream_json["connections"]["idle"] = connections_idle;
			upstream_json["connections"]["busy"] = upstream->connections_busy_.load();
			upstream_json["connections"]["reopened"] = upstream->connections_reopened_.load();

			upstream_json["responses"]["1xx"] = upstream->responses_1xx_.load();
			upstream_json["responses"]["2xx"] = upstream->responses_2xx_.load();
			upstream_json["responses"]["3xx"] = upstream->responses_3xx_.load();
			upstream_json["responses"]["4xx"] = upstream->responses_4xx_.load();
			upstream_json["responses"]["5xx"] = upstream->responses_5xx_.load();
			upstream_json["responses"]["tot"] = upstream->responses_tot_.load();
			upstream_json["responses"]["health"] = upstream->responses_health_.load();

			if (options == options::include_connections)
			{
				// todo
			}

			result.emplace_back(upstream_json);
		}
	}

	std::string to_string(const std::string& workspace_id, options options)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };

		std::ostringstream ss;

		for (auto& upstream : upstreams_)
		{
			auto connections_busy_ = upstream->connections_busy_.load();
			auto connections_total = upstream->connections_total_.load();
			auto connections_idle = connections_total - connections_busy_;
			auto upstream_state = "up";

			if (upstream->state_ == upstream::state::drain)
				upstream_state = "drain";
			else if (upstream->state_ == upstream::state::down)
				upstream_state = "down";

			ss << upstream->base_url_ << ", "
			   << "/" << workspace_id << upstream->id_ << ", " << upstream_state
			   << ", connections(total: " << std::to_string(connections_total) << ", "
			   << "idle: " << std::to_string(connections_idle) << ", busy: " << std::to_string(connections_busy_)
			   << ", reopened: " << std::to_string(upstream->connections_reopened_) << ")"
			   << ", 1xx: " << std::to_string(upstream->responses_1xx_)
			   << ", 2xx: " << std::to_string(upstream->responses_2xx_)
			   << ", 3xx: " << std::to_string(upstream->responses_3xx_)
			   << ", 4xx: " << std::to_string(upstream->responses_4xx_)
			   << ", 5xx: " << std::to_string(upstream->responses_5xx_)
			   << ", tot: " << std::to_string(upstream->responses_tot_) << ", rps: " << std::to_string(upstream->rate_)

			   << ", health: " << std::to_string(upstream->responses_health_) << "\n";

			if (options == options::include_connections)
			{
				for (const auto& connection : upstream->connections())
					connection->to_string(ss);
			}
		}
		return ss.str();
	}

	class upstream
	{
	public:
		using containter_type = std::vector<std::unique_ptr<http::async::upstreams::connection<upstream>>>;
		using iterator = containter_type::iterator;

		enum class state
		{
			up,
			drain,
			down
		};

		upstream(asio::io_context& io_context, const std::string& base_url, const std::string& id)
			: base_url_(base_url), io_context_(io_context), id_(id)
		{
			auto end_of_scheme = base_url.find_first_of(':');
			auto start_of_host = end_of_scheme + 3;

			auto start_of_port = base_url.find_first_of(':', start_of_host);
			auto start_of_path = base_url.find_first_of('/', start_of_host);

			if (start_of_path == std::string::npos) start_of_path = base_url_.size();

			if (start_of_port != std::string::npos)
			{
				port_ = base_url.substr(start_of_port + 1, start_of_path - (start_of_port + 1));
			}
			else
			{
				port_ = "80";
				start_of_port = start_of_path;
			}

			host_ = base_url.substr(start_of_host, start_of_port - start_of_host);

			state_ = state::up;
		}

		~upstream()
		{
			std::unique_lock<std::mutex> lock_guard{ connection_mutex_ };
			state_ = state::down;

			assert(connections_busy_ == 0);
			assert(state_ == state::down);

			connections_.clear();
		}

		void update_status_code_metrics(std::int32_t status)
		{
			assert(status >= 100);
			assert(status < 600);

			if (status >= 100 && status < 200) responses_1xx_++;
			if (status >= 200 && status < 300) responses_2xx_++;
			if (status >= 300 && status < 400) responses_3xx_++;
			if (status >= 400 && status < 500) responses_4xx_++;
			if (status >= 500 && status < 600) responses_5xx_++;

			responses_tot_++;
		}

		void update_health_check_metrics()
		{
			responses_health_++;
			auto responses_diff = responses_tot_ - responses_prev_;

			rate_.store(static_cast<std::uint16_t>(responses_diff / 2));

			responses_prev_.store(responses_tot_);		
		}

		containter_type& connections() { return connections_; }

		std::atomic<std::uint16_t> connections_busy_{ 0 };
		std::atomic<std::size_t> connections_total_{ 0 };
		std::atomic<std::uint16_t> connections_reopened_{ 0 };

		std::atomic<std::uint16_t> responses_1xx_{ 0 };
		std::atomic<std::uint16_t> responses_2xx_{ 0 };
		std::atomic<std::uint16_t> responses_3xx_{ 0 };
		std::atomic<std::uint16_t> responses_4xx_{ 0 };
		std::atomic<std::uint16_t> responses_5xx_{ 0 };
		std::atomic<std::uint16_t> responses_tot_{ 0 };
		std::atomic<std::uint16_t> responses_prev_{ 0 };
		std::atomic<std::uint16_t> responses_health_{ 0 };
		std::atomic<std::uint16_t> rate_{ 0 };

		std::string host() const
		{
			if (port_ == "80" || port_ == "443")
				return host_;
			else
				return host_ + ":" + port_;
		}

		const std::string& base_url() const { return base_url_; }
		const std::string& id() const { return id_; }
		void set_state(upstream::state state) { state_ = state; }
		upstream::state get_state() const { return state_; }

		void add_connection()
		{
			std::lock_guard<std::mutex> g{ connection_mutex_ };

			if (state_ != upstream::state::drain)
			{
				connections_.erase(
					std::remove_if(
						connections_.begin(),
						connections_.end(),
						[](const std::unique_ptr<connection<upstream>>& connection) {
							return connection->is_removable();
						}),
					connections_.end());

				connections_.emplace_back(new connection<upstream>{ io_context_, host_, port_, *this });
				connections_total_ = connections_.size();
			}
		}

		std::atomic<upstream::state> state_{ state::down };
		std::string base_url_;
		asio::io_context& io_context_;
		std::string host_;
		std::string port_;
		std::string id_;
		containter_type connections_;
		std::mutex connection_mutex_;
	};

	using containter_type = std::vector<std::unique_ptr<upstream>>;
	using iterator = containter_type::iterator;
	using connection_type = http::async::upstreams::connection<upstream>;

	containter_type upstreams_;
	std14::shared_mutex upstreams_lock_;

	upstream& get_upstream(const std::string& base_url)
	{
		std14::shared_lock<std14::shared_mutex> g{ upstreams_lock_ };
		auto result
			= std::find_if(upstreams_.begin(), upstreams_.end(), [base_url](const std::unique_ptr<upstream>& rhs) {
				  return (rhs->base_url_ == base_url);
			  });

		return *result->get();
	}

	upstream& add_upstream(asio::io_context& io_context, const std::string& base_url, const std::string& id)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };
		upstreams_.emplace_back(new upstream(io_context, base_url, id));

		return *(upstreams_.back().get());
	}

	void erase_upstream(const std::string& base_url)
	{
		std::unique_lock<std14::shared_mutex> g{ upstreams_lock_ };

		auto upstream_to_remove
			= std::find_if(upstreams_.cbegin(), upstreams_.cend(), [base_url](const std::unique_ptr<upstream>& rhs) {
				  return (rhs->base_url_ == base_url);
			  });

		if (upstream_to_remove != upstreams_.cend())
		{
			upstreams_.erase(upstream_to_remove);
		}
	}

	class next_upstream
	{
	public:
		enum class reason
		{
			not_applicable,
			connection_failed,
			error_503,
			error_502
		};

		next_upstream() = default;

		next_upstream(reason reson_for_next_upstream, const upstream* previous_upstream)
			: previous_upstream_(previous_upstream), reason_(reson_for_next_upstream)
		{
		}

		const upstream& previous_upstream() const { return *previous_upstream_; }
		const upstream* previous_upstream_{ nullptr };

		reason next_upstream_reason() const { return reason_; };
		reason reason_{ reason::not_applicable };
	};

	bool async_upstream_request(std::function<void(connection_type&)> forward_handler, lgr::logger& logger)
	{
		bool result = false;
		static std::atomic<std::uint8_t> rr{ 0 };

		std14::shared_lock<std14::shared_mutex> upstreams_guard{ upstreams_lock_ };

		auto selected_upstream = upstreams_.cbegin() + (++rr % (upstreams_.empty() ? 1 : upstreams_.size()));

		for (auto probe_upstream = upstreams_.cbegin(); probe_upstream != upstreams_.cend(); probe_upstream++)
		{
			auto selected_upstream_connections_total = selected_upstream->get()->connections_total_.load();
			auto selected_upstream_connections_free = selected_upstream->get()->connections_total_.load()
													  - selected_upstream->get()->connections_busy_.load();

			auto probe_upstream_connections_busy = selected_upstream->get()->connections_busy_.load();
			auto probe_upstream_connections_total = probe_upstream->get()->connections_total_.load();
			auto probe_upstream_connections_free = probe_upstream_connections_total - probe_upstream_connections_busy;

			auto probe_upstream_state = probe_upstream->get()->state_.load();
			auto selected_upstream_state = selected_upstream->get()->state_.load();

			if ((probe_upstream_state == upstream::state::up) && selected_upstream_state != upstream::state::up)
				selected_upstream = probe_upstream;

			if ((probe_upstream->get()->state_ == upstream::state::up)
				&& (selected_upstream_connections_total > probe_upstream_connections_total)
				&& (selected_upstream_connections_free < probe_upstream_connections_free))
			{
				selected_upstream = probe_upstream;
			}
		}

		if (selected_upstream != upstreams_.cend() && (selected_upstream->get()->state_ == upstream::state::up))
		{
			bool found = false;
			do
			{
				std::unique_lock<std::mutex> connections_guard{ selected_upstream->get()->connection_mutex_ };
				asio::error_code error_code;
				for (auto& connection : selected_upstream->get()->connections_)
				{
					// Select the least connected upstream
					auto expected_state = http::async::upstreams::connection_type::state::idle;

					if (connection->get_state().compare_exchange_strong(
							expected_state, http::async::upstreams::connection_type::state::waiting)
						== true)
					{
						auto selected_connection = connection.get();
						connections_guard.unlock();
						++(selected_upstream->get()->connections_busy_);

						forward_handler(*selected_connection);

						found = true;
						break;
					}
				}

				if (found == false)
				{

					if (error_code)
					{
						return false;
					}
					else
					{
						logger.info("new upstream connection to {s}\n", selected_upstream->get()->base_url());
						connections_guard.unlock();
						selected_upstream->get()->add_connection();
					}
				}
			} while (found == false);

			result = true;
		}
		else
		{
			logger.info("failed to find a suitable upstream\n");
			result = false;
		}
		return result;
	}
};

class server : public http::server
{
public:
	template <class connection_handler_derived, class socket_t>
	class connection_handler_base : public std::enable_shared_from_this<connection_handler_derived>
	{
	protected:
		asio::io_context& service_;
		// asio::io_context::strand write_strand_;
		asio::streambuf in_packet_{ 8192 };
		http::transfer_encoding_chunked_parser chunked_parser_{};

		std::deque<std::string> write_buffer_;
		http::session_handler session_handler_;
		server& server_;
		http::api::routing routing_{};
		http::protocol protocol_;

		std::vector<asio::ip::network_v6> private_ip_white_list_{};
		std::vector<asio::ip::network_v6> public_ip_white_list_{};

		bool private_base_request_{ false };
		asio::steady_timer queued_timer_;
		asio::steady_timer timeout_timer_;

		connection_handler_base(
			asio::io_context& service, server& server, http::configuration& configuration, protocol protocol)
			: service_(service)
			, session_handler_(
				  configuration.get<std::string>("server", "server_no_id"),
				  configuration.get<int>("keepalive_count", 1024 * 8),
				  configuration.get<int>("keepalive_max", 5),
				  configuration.get<int>("gzip_min_size", 1024),
				  protocol)
			, server_(server)
			, protocol_(protocol)
			, queued_timer_(service)
			, timeout_timer_(service)
		{
			server_.logger_.info(
				"{s}_connection_handler: start {u}\n", http::to_string(protocol_), reinterpret_cast<uintptr_t>(this));

			for (const auto& allowed_range_spec :
				 util::split(configuration.get<std::string>("private_ip_white_list", "::/0"), ";"))
			{
				auto spec = util::split(allowed_range_spec, "/");

				auto allowed_network = asio::ip::network_v6(
					asio::ip::address_v6::from_string(spec[0]),
					static_cast<std::uint16_t>(std::strtoul(spec[1].data(), nullptr, 10)));

				private_ip_white_list_.emplace_back(allowed_network);
			}

			for (const auto& allowed_range_spec :
				 util::split(configuration.get<std::string>("public_ip_white_list", "::/0"), ";"))
			{
				auto spec = util::split(allowed_range_spec, "/");

				auto allowed_network = asio::ip::network_v6(
					asio::ip::address_v6::from_string(spec[0]),
					static_cast<std::uint16_t>(std::strtoul(spec[1].data(), nullptr, 0)));

				public_ip_white_list_.emplace_back(allowed_network);
			}
		}

		virtual ~connection_handler_base()
		{
			server_.logger_.info(
				"{s}_connection_handler: close {u}\n", http::to_string(protocol_), reinterpret_cast<uintptr_t>(this));
			server_.manager().connections_current().operator--();
		}

		connection_handler_base(connection_handler_base const&) = delete;
		void operator==(connection_handler_base const&) = delete;

		connection_handler_base(connection_handler_base&&) = delete;

		connection_handler_base& operator=(const connection_handler_base&) = delete;
		connection_handler_base& operator=(connection_handler_base&&) = delete;

		socket_t& socket_base() { return static_cast<connection_handler_derived*>(this)->socket(); };
		std::string remote_address_base() { return static_cast<connection_handler_derived*>(this)->remote_address(); };

		bool is_remote_address_allowed_base(const std::vector<asio::ip::network_v6>& networks) const
		{
			return static_cast<const connection_handler_derived*>(this)->is_remote_address_allowed(networks);
		};

		virtual void start(){};
		virtual void stop() { --server_.manager().connections_current(); }

		void set_timeout()
		{
			timeout_timer_.expires_from_now(std::chrono::seconds(session_handler_.keepalive_max()));

			auto me = this->shared_from_this();
			timeout_timer_.async_wait([me](asio::error_code const& ec) {
				if (!ec) me->stop();
			});
		}

		void cancel_timeout()
		{
			asio::error_code ec;
			timeout_timer_.cancel(ec);
		}

		void read_request_headers()
		{
			// Header
			in_packet_.consume(in_packet_.size());
			auto me = this->shared_from_this();
			asio::async_read_until(
				this->socket_base(), in_packet_, "\r\n\r\n", [me](asio::error_code const& ec, std::size_t bytes_xfer) {
					me->read_request_headers_complete(ec, bytes_xfer);
				});
		}

		void read_request_headers_complete(asio::error_code const& ec, std::size_t bytes_transferred)
		{
			if (!ec)
			{
				session_handler_.t0() = std::chrono::steady_clock::now();
				http::request_parser::result_type result;

				std::tie(result, std::ignore) = session_handler_.parse_request(
					asio::buffers_begin(in_packet_.data()), asio::buffers_begin(in_packet_.data()) + bytes_transferred);

				in_packet_.consume(bytes_transferred);
				session_handler_.request().set(
					"X-Forwarded-For", session_handler_.request().get("X-Forwarded-For", this->remote_address_base()));

				private_base_request_ = session_handler_.request().target().find(server_.router_.private_base_, 0) == 0;

				if (private_base_request_ == true)
				{
					session_handler_.client_allowed(is_remote_address_allowed_base(private_ip_white_list_));
					server_.manager().requests_current(private_base_request_);
				}
				else
				{
					session_handler_.client_allowed(is_remote_address_allowed_base(public_ip_white_list_));
					++server_.manager().requests_current(private_base_request_);
				}

				if (result == http::request_parser::good)
				{
					this->cancel_timeout();
					auto content_length = session_handler_.request().content_length();

					if (session_handler_.request().get<std::string>("Expect", "") == "100-continue")
						asio::write(this->socket_base(), asio::buffer("HTTP/1.1 100 Continue\r\n\r\n"));

					if (content_length == http::request_message::content_length_invalid)
					{
						session_handler_.response().set("Connection", "Close");
						session_handler_.response().status(http::status::length_required);
						write_response();
					}
					else if (content_length > server_.max_request_content_length())
					{
						session_handler_.response().set("Connection", "Close");
						session_handler_.response().status(http::status::payload_too_large);
						write_response();
					}
					else if (content_length > 0)
					{
						this->session_handler_.request().body() += std::string(
							asio::buffers_begin(in_packet_.data()), asio::buffers_end(in_packet_.data()));
						auto s = asio::buffers_end(in_packet_.data()) - asio::buffers_begin(in_packet_.data());

						in_packet_.consume(s);

						this->session_handler_.request().body().reserve(session_handler_.request().content_length());

						read_request_body();
					}
					else
					{
						if (session_handler_.request().chunked() == false)
						{
							read_request_body_complete(asio::error_code{}, 0, upstreams::next_upstream{});
						}
						else
						{
							chunked_parser_.reset();
							read_request_chunked_body(bytes_transferred);
						}
					}
				}
				else if (result == http::request_parser::bad)
				{
					this->cancel_timeout();
					session_handler_.response().set("Connection", "Close");
					session_handler_.response().status(http::status::bad_request);
					write_response();
				}
				else
				{
					read_request_headers();
				}
			}
			else
			{
				if (ec == asio::error::not_found)
				{
					session_handler_.response().status(http::status::payload_too_large);
					write_response();
				}
				else
				{
					stop();
					server_.logger_.debug("{s}\n", ec.message());
					// if (ec == asio::error::operation_aborted)
					//{
					//	session_handler_.response().status(http::status::request_timeout);
					//	write_response();
					//}
					// else
					//	stop();
				}
			}
		}

		void read_request_body()
		{
			asio::error_code ec;
			if (session_handler_.request().body().size() < session_handler_.request().content_length())
			{
				auto me = this->shared_from_this();
				asio::async_read(
					this->socket_base(),
					in_packet_,
					asio::transfer_at_least(1),
					[me](asio::error_code const& ec, std::size_t bytes_xfer) {
						if (!ec)
						{
							auto content_length = me->session_handler_.request().content_length();
							auto body_size = me->session_handler_.request().body().length();

							size_t chunk_size
								= asio::buffers_end(me->in_packet_.data()) - asio::buffers_begin(me->in_packet_.data());

							if (content_length - body_size < chunk_size) chunk_size = content_length - body_size;

							me->session_handler_.request().body().append(
								asio::buffers_begin(me->in_packet_.data()), asio::buffers_end(me->in_packet_.data()));

							me->in_packet_.consume(chunk_size);

							body_size = me->session_handler_.request().body().length();

							if (body_size < content_length)
							{
								me->read_request_body();
							}
							else
							{
								me->read_request_body_complete(ec, bytes_xfer, upstreams::next_upstream{});
							}
						}
						else
						{
							me->read_request_body_complete(ec, bytes_xfer, upstreams::next_upstream{});
						}
					});
			}
			else if (session_handler_.request().body().size() == session_handler_.request().content_length())
			{
				read_request_body_complete(ec, session_handler_.request().body().size(), upstreams::next_upstream{});
			}
			else
			{
				ec.assign(1, ec.category());
				read_request_body_complete(ec, 0, upstreams::next_upstream{});
			}
		}

		void read_request_chunked_body(size_t bytes_transferred)
		{
			http::transfer_encoding_chunked_parser::result_type parse_result;
			auto buffer_begin = asio::buffers_begin(in_packet_.data());
			auto buffer_end = asio::buffers_end(in_packet_.data());

			decltype(buffer_begin) c;

			if ((buffer_end - buffer_begin) == 0)
			{
				// Curl bug? no zero chunk is send when post body is empty?
				read_request_body_complete(asio::error_code{}, bytes_transferred, upstreams::next_upstream{});
			}

			std::tie(parse_result, c) = chunked_parser_.parse(session_handler_.request(), buffer_begin, buffer_end);

			in_packet_.consume(c - asio::buffers_begin(in_packet_.data()));

			if (parse_result == transfer_encoding_chunked_parser::result_type::good)
				read_request_body_complete(asio::error_code{}, bytes_transferred, upstreams::next_upstream{});
			else
			{
				auto me = this->shared_from_this();
				asio::async_read(
					this->socket_base(),
					in_packet_,
					asio::transfer_at_least(1),
					[me](asio::error_code const& ec, std::size_t bytes_xfer) {
						if (!ec)
						{
							me->read_request_chunked_body(bytes_xfer);
						}
						else
						{
							me->read_request_body_complete(ec, bytes_xfer, upstreams::next_upstream{});
						}
					});
			}
		}

		void read_request_body_complete(
			asio::error_code const& ec, std::size_t, const upstreams::next_upstream& next_upstream)
		{
			if (!ec)
			{
				if (next_upstream.next_upstream_reason() == upstreams::next_upstream::reason::not_applicable)
				{
					session_handler_.request().set(
						"X-Forwarded-For", session_handler_.request().get("X-Forwarded-For", remote_address_base()));

					routing_ = session_handler_.handle_request(server_.router_);

					if (server_.logger_.current_extended_log_level() == lgr::level::debug)
					{
						server_.logger_.debug("request:\n{s}\n", http::to_dbg_string(session_handler_.request()));
					}
				}
				else
				{
					session_handler_.response().clear();

					server_.logger_.error(
						"{s} failed. retry using another upstream.\n", next_upstream.previous_upstream().id());
				}

				session_handler_.t2() = std::chrono::steady_clock::now();

				auto queue = session_handler_.request().template get_attribute<std::int16_t>("queued", 0);

				if (queue)
				{
					queued_timer_.expires_from_now(std::chrono::seconds{ queue });
					auto original_ec = ec;
					session_handler_.request().template set_attribute<std::int16_t>("queued", 0);

					auto me = this->shared_from_this();
					queued_timer_.async_wait([me, next_upstream, original_ec](const asio::error_code&) {
						me->read_request_body_complete(original_ec, size_t{ 0 }, next_upstream);
					});

					return;
				}

				auto upstreams
					= session_handler_.request().template get_attribute<http::async::upstreams*>("proxy_pass", nullptr);

				if (upstreams)
				{
					auto start_async_result = upstreams->async_upstream_request(
						[this](http::async::upstreams::connection_type& connection) {
							init_connection_to_upstream(connection);
						},
						server_.logger());

					if (start_async_result == false)
					{
						session_handler_.response().status(http::status::service_unavailable);
						write_response();
					}
				}
				else
					write_response();
			}
			else
			{
				session_handler_.response().status(http::status::bad_request);
				write_response();
			}
		}

		void init_connection_to_upstream(http::async::upstreams::connection_type& upstream_connection)
		{
			asio::error_code error;

			if (upstream_connection.socket().is_open())
			{
				char peek_buffer[1];
				upstream_connection.socket().non_blocking(true);
				upstream_connection.socket().receive(
					asio::buffer(peek_buffer), asio::ip::tcp::socket::message_peek, error);
				upstream_connection.socket().non_blocking(false);
			}

			if (error != asio::error::would_block)
			{
				asio::error_code error_1;
				if (upstream_connection.socket().is_open())
				{
					upstream_connection.socket().shutdown(asio::socket_base::shutdown_send, error_1);
					upstream_connection.socket().close(error_1);

					++upstream_connection.owner().connections_reopened_;
				}

				auto me = this->shared_from_this();

				upstream_connection.resolver_.async_resolve(
					asio::ip::tcp::v4(),
					upstream_connection.host_,
					upstream_connection.port_,
					[me, &upstream_connection](asio::error_code error_code, asio::ip::tcp::resolver::iterator it) {
						if (error_code) return;

						auto me_1 = me->shared_from_this();

						asio::async_connect(
							upstream_connection.socket(),
							it,
							[me_1,
							 &upstream_connection](asio::error_code error_code, asio::ip::tcp::resolver::iterator it) {
								if (error_code)
								{
									// failed
									upstream_connection.error();
									upstream_connection.owner().set_state(
										http::async::upstreams::upstream::state::drain);
								}
								else
								{
									me_1->write_upstream_request(upstream_connection);
								}
							});
					});
			}
			else
			{
				// no need to reconnect, connection still open (due to keepalive)
				write_upstream_request(upstream_connection);
			}
		}

		void write_upstream_request(http::async::upstreams::connection_type& upstream_connection)
		{

			session_handler_.request().target(session_handler_.request().url_requested());
			session_handler_.request().reset_if_exists("Expect");

			write_buffer_.emplace_back(http::to_string(session_handler_.request()));

			auto me = this->shared_from_this();

			asio::async_write(
				upstream_connection.socket(),
				asio::buffer(write_buffer_.front()),
				[me, &upstream_connection](asio::error_code const& ec, std::size_t) {
					me->write_buffer_.pop_front();

					if (!ec)
						me->read_upstream_response_headers(upstream_connection);
					else
						me->read_upstream_response_body_complete(upstream_connection, ec);
				});
		}

		void read_upstream_response_headers(http::async::upstreams::connection_type& upstream_connection)
		{
			auto me = this->shared_from_this();

			upstream_connection.buffer_.clear();

			asio::async_read_until(
				upstream_connection.socket(),
				asio::dynamic_buffer(upstream_connection.buffer_),
				"\r\n\r\n",
				[me, &upstream_connection](asio::error_code ec, size_t bytes_red) {
					if (!ec)
						me->read_upstream_response_headers_complete(upstream_connection, bytes_red);
					else
						me->read_upstream_response_body_complete(upstream_connection, ec);
				});
		}

		void read_upstream_response_headers_complete(
			http::async::upstreams::connection_type& upstream_connection, size_t bytes_red)
		{
			http::response_parser response_parser;
			http::response_parser::result_type result;
			const char* c = nullptr;

			std::tie(result, c) = response_parser.parse(
				session_handler_.response(),
				upstream_connection.buffer_.data(),
				upstream_connection.buffer_.data() + bytes_red);

			if (result == http::response_parser::result_type::good)
			{
				// TODO: enable via config?
				// session_handler_.request().set("X-Request-ID", upstream_connection.id());
				// session_handler_.response().set("X-Upstream-Server", upstream_connection.id());

				auto content_length = session_handler_.response().content_length();

				if (content_length > 0 && content_length != http::request_message::content_length_invalid)
				{
					auto content_already_received = static_cast<size_t>(
						upstream_connection.buffer_.data() + upstream_connection.buffer_.size() - c);

					session_handler_.response().body().reserve(content_length);

					session_handler_.response().body().assign(c, content_already_received);

					if (content_already_received < content_length)
					{
						read_upstream_response_body(upstream_connection);
					}
					else
					{
						read_upstream_response_body_complete(upstream_connection, asio::error_code{});
					}
				}
				else if (session_handler_.response().chunked())
				{
					session_handler_.response().status(http::status::internal_server_error);
					session_handler_.response().body() = "chunked upstream response received\n";
					read_upstream_response_body_complete(upstream_connection, asio::error_code{});
				}
				else
				{
					read_upstream_response_body_complete(upstream_connection, asio::error_code{});
				}
			}
		}

		void read_upstream_response_body(http::async::upstreams::connection_type& upstream_connection)
		{
			asio::error_code ec;
			if (session_handler_.response().body().size() < session_handler_.response().content_length())
			{
				auto me = this->shared_from_this();
				upstream_connection.buffer_.clear();
				asio::async_read(
					upstream_connection.socket(),
					asio::dynamic_buffer(upstream_connection.buffer_),
					asio::transfer_at_least(1),
					[me, &upstream_connection](const asio::error_code& ec, std::size_t bytes_xfer) {
						if (!ec)
						{
							auto content_length = me->session_handler_.response().content_length();

							me->session_handler_.response().body().append(
								upstream_connection.buffer_.data(), bytes_xfer);

							if (me->session_handler_.response().body().length() < content_length)
							{
								me->read_upstream_response_body(upstream_connection);
							}
							else
							{
								me->read_upstream_response_body_complete(upstream_connection, ec);
							}
						}
						else
						{
							me->read_upstream_response_body_complete(upstream_connection, ec);
						}
					});
			}
			else if (session_handler_.response().body().size() == session_handler_.response().content_length())
			{
				read_upstream_response_body_complete(upstream_connection, ec);
			}
			else
			{
				assert(1 == 0);
				read_upstream_response_body_complete(upstream_connection, ec);
			}
		}

		void read_upstream_response_body_complete(
			http::async::upstreams::connection_type& upstream_connection, asio::error_code ec)
		{
			if (ec)
			{
				upstream_connection.error();
				session_handler_.response().reset();
				session_handler_.response().status(http::status::service_unavailable);
				write_response();
				return;
			}
			else if (upstream_connection.should_drain())
			{
				upstream_connection.drain();
				write_response();
				return;
			}

			auto status_code = http::status::to_int(session_handler_.response().status());

			upstream_connection.owner().update_status_code_metrics(status_code);

			if (session_handler_.response().connection_close() == true)
			{
				asio::ip::tcp::resolver resolver(upstream_connection.socket().get_executor());

				auto me = this->shared_from_this();

				upstream_connection.resolver_.async_resolve(
					asio::ip::tcp::v4(),
					upstream_connection.host_,
					upstream_connection.port_,
					[me, &upstream_connection](asio::error_code error_code, asio::ip::tcp::resolver::iterator it) {
						if (error_code) return;

						auto me_1 = me->shared_from_this();

						asio::async_connect(
							upstream_connection.socket(),
							it,
							[me_1,
							 &upstream_connection](asio::error_code error_code, asio::ip::tcp::resolver::iterator it) {
								if (error_code)
								{
									// failed
									upstream_connection.error();
								}
								else
								{
									upstream_connection.release();
								}
							});
					});
			}
			else
			{
				upstream_connection.release();
			}

			if (session_handler_.response().status() == http::status::service_unavailable)
			{
				read_request_body_complete(
					asio::error_code{},
					0,
					upstreams::next_upstream{
						upstreams::next_upstream::reason::error_503,
						&upstream_connection.owner(),
					});
			}
			else
			{
				write_response();
			}
		}

		void write_response()
		{
			auto me = this->shared_from_this();

			session_handler_.handle_response<http::api::router<>>(routing_, session_handler_.response().status());

			write_buffer_.emplace_back(http::to_string(session_handler_.response()));

			asio::async_write(
				socket_base(), asio::buffer(this->write_buffer_.front()), [me](asio::error_code, std::size_t) {
					me->write_buffer_.pop_front();
					me->write_response_complete();
				});
		}

		void write_response_complete()
		{
			if (routing_.is_private_base_request())
				private_base_request_ = true;

			if (routing_.match_result() == http::api::router_match::match_found)
			{
				routing_.the_route().metric_response_latency(
					std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::steady_clock::now() - session_handler_.t2())
						.count());

				if (server_.logger_.current_extended_log_level() == lgr::level::debug)
				{
					server_.logger_.debug("response:\n{s}\n", http::to_dbg_string(session_handler_.response()));
				}

				auto log_msg
					= server_.manager().log_access(session_handler_, routing_.the_route().route_metrics()) + "\n";

				if (private_base_request_ == false)
				{
					server_.manager().update_status_code_metrics(
						http::status::to_int(session_handler_.response().status()));

					server_.logger_.access_log(log_msg);
					--server_.manager().requests_current(private_base_request_);
				}
				else if (private_base_request_ == true)
				{
					server_.logger_.access_log_all(log_msg);
					server_.manager().requests_current(private_base_request_);
				}
			}
			else
			{
				auto log_msg = server_.manager().log_access(session_handler_, http::api::routing::metrics{}) + "\n";

				if (private_base_request_ == false)
				{
					server_.manager().update_status_code_metrics(
						http::status::to_int(session_handler_.response().status()));

					server_.logger_.access_log(log_msg);
				}
				else if (private_base_request_ == true)
				{
					server_.logger_.access_log_all(log_msg);
				}
			}

			if (session_handler_.response().connection_keep_alive())
			{
				session_handler_.reset();
				static_cast<connection_handler_derived*>(this)->start();
			}
			else
			{
				// socket().shutdown(asio::ip::tcp::socket::shutdown_both);
			}
		}
	};

	class connection_handler_http
		: public server::connection_handler_base<connection_handler_http, asio::ip::tcp::socket>
	{
	public:
		connection_handler_http(asio::io_context& service, server& server, http::configuration& configuration)
			: connection_handler_base(service, server, configuration, http::protocol::http), socket_(service)
		{
		}

		asio::ip::tcp::socket& socket() { return socket_; }

		std::string remote_address()
		{
			asio::error_code ec;

			try
			{
				std::string ret = socket_.remote_endpoint().address().to_string(ec);

				if (ec) ret = "?";

				return ret;
			}
			catch (...)
			{
				return "-";
			}
		}

		bool is_remote_address_allowed(const std::vector<asio::ip::network_v6>& networks) const
		{
			auto address = socket_.remote_endpoint().address();
			bool result = false;

			if (address.is_v4())
			{
				// auto address_as_network = asio::ip::network_v4(address.to_v4(), 32);

				// for (const auto& network : networks)
				//{
				//	if (address_as_network.canonical() == network.canonical()) return true;

				//	if (address_as_network.is_subnet_of(network.canonical()) == true) return true;
				//}
			}
			else
			{
				auto address_as_network = asio::ip::network_v6(address.to_v6(), 128);

				for (const auto& network : networks)
				{
					if (address_as_network.canonical() == network.canonical()) return true;

					if (address_as_network.is_subnet_of(network.canonical()) == true) return true;
				}
			}
			return result;
		}

		void start() override
		{
			set_timeout();
			asio::error_code ec;
			socket_.set_option(asio::ip::tcp::no_delay(true), ec);
			if (!ec) read_request_headers();
		}

		void stop() override
		{
			if (socket_.is_open())
			{
				asio::error_code error;
				socket_.shutdown(asio::socket_base::shutdown_send, error);
				socket_.cancel(error);
				socket_.close();
			}
		}

	private:
		asio::ip::tcp::socket socket_;
	};

	class connection_handler_https
		: public server::connection_handler_base<connection_handler_https, asio::ssl::stream<asio::ip::tcp::socket>>
	{

	public:
		connection_handler_https(
			asio::io_context& service,
			server& server,
			http::configuration& configuration,
			asio::ssl::context& ssl_context)
			: connection_handler_base(service, server, configuration, http::protocol::https)
			, socket_(service, ssl_context)
		{
		}

		asio::ssl::stream<asio::ip::tcp::socket>& socket() { return socket_; };

		std::string remote_address()
		{
			asio::error_code ec;

			try
			{
				std::string ret = socket_.lowest_layer().remote_endpoint().address().to_string(ec);

				if (ec) ret = "?";

				return ret;
			}
			catch (...)
			{
				return "-";
			}
		}

		bool is_remote_address_allowed(const std::vector<asio::ip::network_v6>& networks) const
		{
			auto address = socket_.lowest_layer().remote_endpoint().address();
			bool result = false;

			if (address.is_v4())
			{
				// auto address_as_network = asio::ip::network_v4(address.to_v4(), 32);

				// for (const auto& network : networks)
				//{
				//	if (address_as_network.canonical() == network.canonical()) return true;

				//	if (address_as_network.is_subnet_of(network.canonical()) == true) return true;
				//}
			}
			else
			{
				auto address_as_network = asio::ip::network_v6(address.to_v6(), 128);

				for (const auto& network : networks)
				{
					if (address_as_network.canonical() == network.canonical()) return true;

					if (address_as_network.is_subnet_of(network.canonical()) == true) return true;
				}
			}
			return result;
		}

		void start() override
		{
			set_timeout();
			asio::error_code ec;
			socket_.lowest_layer().set_option(asio::ip::tcp::no_delay(true), ec);

			auto me = shared_from_this();
			socket_.async_handshake(asio::ssl::stream_base::server, [me](asio::error_code const& ec) {
				if (ec == asio::ssl::error::stream_truncated)
				{
					// some clients terminate the ssl conneciton without shutdown.
					// ignore and let connection_handler go out of scope to terminate connection.
				}
				else if (ec)
				{
					me->server_.logger().error("{s} when during asyc_handshake\n", ec.message());
				}
				else
				{
					me->set_timeout();
					me->read_request_headers();
				}
			});
		}

		void stop() override
		{
			if (socket_.lowest_layer().is_open())
			{
				asio::error_code error;
				socket_.lowest_layer().shutdown(asio::socket_base::shutdown_send, error);
				socket_.lowest_layer().cancel(error);
				socket_.lowest_layer().close(error);
			}
		}

	private:
		asio::ssl::stream<asio::ip::tcp::socket> socket_;
	};

	using shared_connection_handler_http = std::shared_ptr<server::connection_handler_http>;
	using shared_https_connection_handler_https = std::shared_ptr<server::connection_handler_https>;

public:
	server(http::configuration& configuration)
		: http::server{ configuration }
		, thread_count_(configuration.get<std::uint8_t>("thread_count", static_cast<std::uint8_t>(4)))
		, http_watchdog_idle_timeout_(configuration.get<std::int16_t>("http_watchdog_idle_timeout", 0))
		, http_watchdog_max_requests_concurrent_(
			  configuration.get<std::int16_t>("http_watchdog_max_requests_concurrent", 0))
		, http_use_portsharding_(configuration.get<bool>("http_use_portsharding", false))
		, http_enabled_(configuration.get<bool>("http_enabled", true))
		, http_listen_port_begin_(configuration.get<std::int16_t>("http_listen_port_begin", 3000))
		, http_listen_port_end_(configuration.get<int16_t>("http_listen_port_end", http_listen_port_begin_))
		, http_listen_port_(network::tcp::socket::invalid_socket)
		, http_listen_address_(configuration.get<std::string>("http_listen_address", "::0"))
		, https_use_portsharding_(configuration.get<bool>("https_use_portsharding", false))
		, https_enabled_(configuration.get<bool>("https_enabled", false))
		, https_listen_port_begin_(configuration.get<std::int16_t>(
			  "https_listen_port_begin", configuration.get<int16_t>("http_listen_port_begin") + 1000))
		, https_listen_port_end_(configuration.get<int16_t>("https_listen_port_end", https_listen_port_begin_))
		, https_listen_port_(network::tcp::socket::invalid_socket)
		, https_listen_address_(configuration.get<std::string>("https_listen_address", "::0"))
		, max_request_content_length_(configuration.get<size_t>("max_request_content_length", 1024 * 1024 * 16))
		, io_context_pool_(thread_count_)
		, request_rate_timer_(io_context_pool_.get_io_context())
		, http_acceptor_(io_context_pool_.get_io_context())
		, https_acceptor_(io_context_pool_.get_io_context())
		, https_ssl_context_(asio::ssl::context::tls_server)
	{
		if (https_enabled_)
		{
			asio::error_code error_code;
			auto tls_protocol = configuration_.get<std::string>("https_tls_protocol", "tls_v1.3");

			auto cypher_suite = configuration_.get<std::string>(
				"https_cypher_list",
				"TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-"
				"CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA384:"
				"ECDHE-RSA-AES256-SHA384");

			SSL_CTX_set_cipher_list(https_ssl_context_.native_handle(), cypher_suite.data());

			if (tls_protocol == "tls_v1.3")
			{
				https_ssl_context_.set_options(
					asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2
					| asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1
					| asio::ssl::context::no_tlsv1_2 | asio::ssl::context::single_dh_use | SSL_OP_CIPHER_SERVER_PREFERENCE);
			}
			else if (tls_protocol == "tls_v1.2")
			{
				https_ssl_context_.set_options(
					asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2
					| asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1
					| asio::ssl::context::single_dh_use | SSL_OP_CIPHER_SERVER_PREFERENCE);
			}

			https_ssl_context_.use_certificate_chain_file(
				configuration_.get<std::string>("https_certificate", "server.crt"), error_code);

			if (error_code)
			{
				logger_.error(
					"{s} when loading https_certificate: {s}\n",
					error_code.message(),
					configuration_.get<std::string>("https_certificate", "server.crt"));
			}

			https_ssl_context_.use_private_key_file(
				configuration_.get<std::string>("https_certificate_key", "server.key"),
				asio::ssl::context::pem,
				error_code);

			// https_ssl_context_.set_verify_mode(
			//	asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert | asio::ssl::verify_client_once);

			if (error_code)
			{
				logger_.error(
					"{s} when loading https_certificate_key: {s}\n",
					error_code.message(),
					configuration_.get<std::string>("https_certificate_key", "server.key"));
			}


			//https_ssl_context_.set_options(
			//	asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3
			//		| asio::ssl::context::no_tlsv1 | asio::ssl::context::single_dh_use
			//		| SSL_OP_CIPHER_SERVER_PREFERENCE,
			//	error_code);

			if (error_code)
			{
				logger_.error("{s} when loading https_cypher_list: {s}\n", error_code.message(), cypher_suite);
			}

			if (configuration_.get("https_certificate_verify_file").size() > 0)
			{
				logger_.error(
					"{s} when loading https_certificate_file: {s}\n",
					error_code.message(),
					configuration_.get<std::string>("https_certificate_verify_file", "server.chk"));
			}
		}
	}

	virtual ~server()
	{
		request_rate_timer_.cancel();
		if (is_active() || is_activating()) this->stop();

		logger_.debug("server deleted\n");
	}

	void on_server_timer(const asio::error_code&)
	{
		manager().update_rate();

		request_rate_timer_.expires_from_now(std::chrono::seconds(1));
		request_rate_timer_.async_wait([this](const asio::error_code& ec) { on_server_timer(ec); });
	}

	virtual server::state start() override
	{
		request_rate_timer_.expires_from_now(std::chrono::seconds(1));
		request_rate_timer_.async_wait([this](const asio::error_code& ec) { on_server_timer(ec); });

		auto http_handler = std::make_shared<server::connection_handler_http>(
			io_context_pool_.get_io_context(), *this, configuration_);

		auto https_handler = std::make_shared<server::connection_handler_https>(
			io_context_pool_.get_io_context(), *this, configuration_, https_ssl_context_);

		asio::ip::tcp::endpoint http_endpoint(asio::ip::make_address(http_listen_address_), http_listen_port_begin_);
		asio::ip::tcp::endpoint https_endpoint(asio::ip::make_address(https_listen_address_), https_listen_port_begin_);

		asio::error_code ec;

		auto http_listen_port_probe = http_listen_port_begin_;

		for (; http_listen_port_probe <= http_listen_port_end_; http_listen_port_probe++)
		{
			http_endpoint.port(http_listen_port_probe);
			http_acceptor_.open(http_endpoint.protocol());

			if (http_listen_port_begin_ == http_listen_port_end_)
			{
				http_acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
			}

			http_acceptor_.bind(http_endpoint, ec);
			if (ec)
			{
				http_listen_port_probe++;
				continue;
			}
			else
			{
				http_listen_port_probe = http_acceptor_.local_endpoint().port();
				break;
			}
		}

		if (ec)
			throw std::runtime_error(std::string(
				"cannot bind/listen to port in range: [ " + std::to_string(http_listen_port_begin_) + ":"
				+ std::to_string(http_listen_port_end_) + " ]"));

		http_acceptor_.listen(asio::socket_base::max_connections);
		configuration_.set("http_listen_port", std::to_string(http_listen_port_probe));

		if (configuration_.get<std::string>("http_listen_address", "::0") == "::0")
		{
			http_this_server_base_host_
				= util::fully_qualified_hostname()
				  + (http_listen_port_probe == 80 ? "" : ":" + std::to_string(http_listen_port_probe));

			configuration_.set("http_this_server_base_host", http_this_server_base_host_);

			configuration_.set("http_this_server_base_url", "http://" + http_this_server_base_host_);
		}

		configuration_.set("http_this_server_local_url", "http://localhost:" + std::to_string(http_listen_port_probe));

		logger_.info("http listener on port: {d} started\n", http_listen_port_probe);
		http_listen_port_.store(http_listen_port_probe);

		if (https_enabled_)
		{
			// setup listener for https if enabled
			auto https_listen_port_probe = https_listen_port_begin_;

			for (; https_listen_port_probe <= https_listen_port_end_; https_listen_port_probe++)
			{
				https_endpoint.port(https_listen_port_probe);
				https_acceptor_.open(https_endpoint.protocol());

				if (https_listen_port_begin_ == https_listen_port_end_)
				{
					https_acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
				}

				https_acceptor_.bind(https_endpoint, ec);
				if (ec)
				{
					https_listen_port_probe++;
					continue;
				}
				else
					break;
			}

			if (ec)
				throw std::runtime_error(std::string(
					"cannot bind/listen to port in range: [ " + std::to_string(https_listen_port_begin_) + ":"
					+ std::to_string(https_listen_port_end_) + " ]"));

			https_acceptor_.listen(asio::socket_base::max_connections);

			configuration_.set("https_listen_port", std::to_string(https_listen_port_probe));
			if (configuration_.get<std::string>("https_listen_address", "::0") == "::0")
			{
				https_this_server_base_host_
					= util::fully_qualified_hostname()
					  + (https_listen_port_probe == 443 ? "" : ":" + std::to_string(https_listen_port_probe));

				configuration_.set("https_this_server_base_host", https_this_server_base_host_);

				configuration_.set("https_this_server_base_url", "https://" + https_this_server_base_host_);
			}

			configuration_.set(
				"https_this_server_local_url",
				"https://localhost:" + configuration_.get<std::string>("https_listen_port"));

			logger_.info("https listener on port: {d} started\n", https_listen_port_probe);
			http_listen_port_.store(https_listen_port_probe);
		}

		http_acceptor_.async_accept(http_handler->socket(), [this, http_handler](const asio::error_code error) {
			this->handle_new_connection(http_handler, error);
		});

		if (https_enabled_)
		{

			https_acceptor_.async_accept(
				https_handler->socket().lowest_layer(), [this, https_handler](const asio::error_code error) {
					this->handle_new_https_connection(https_handler, error);
				});
		}

		io_context_pool_.run();

		state_.store(http::server::state::active);
		return state_;
	}

	virtual server::state stop() override
	{
		state_.store(state::not_active);

		io_context_pool_.stop();

		return state_;
	}

	asio::io_context& get_io_context() { return io_context_pool_.get_io_context(); }

private:
	void handle_new_connection(const shared_connection_handler_http& handler, const asio::error_code error)
	{
		auto new_handler = std::make_shared<server::connection_handler_http>(
			io_context_pool_.get_io_context(), *this, configuration_);

		http_acceptor_.async_accept(new_handler->socket(), [this, new_handler](const asio::error_code error) {
			this->handle_new_connection(new_handler, error);
		});

		if (error)
		{
			return;
		}

		++manager().connections_accepted();
		++manager().connections_current();

		handler->start();
	}

	void handle_new_https_connection(const shared_https_connection_handler_https& handler, const asio::error_code error)
	{
		auto new_handler = std::make_shared<server::connection_handler_https>(
			io_context_pool_.get_io_context(), *this, configuration_, https_ssl_context_);

		https_acceptor_.async_accept(
			new_handler->socket().lowest_layer(), [this, new_handler](const asio::error_code error) {
				this->handle_new_https_connection(new_handler, error);
			});

		if (error)
		{
			return;
		}

		++manager().connections_accepted();
		++manager().connections_current();

		handler->start();
	}

	std::uint8_t thread_count_;
	std::int16_t http_watchdog_idle_timeout_;
	std::int16_t http_watchdog_max_requests_concurrent_;

	bool http_use_portsharding_;
	bool http_enabled_;
	std::uint16_t http_listen_port_begin_;
	std::uint16_t http_listen_port_end_;
	std::atomic<network::socket_t> http_listen_port_;
	std::string http_listen_address_;

	bool https_use_portsharding_;
	bool https_enabled_;
	std::uint16_t https_listen_port_begin_;
	std::uint16_t https_listen_port_end_;
	std::atomic<network::socket_t> https_listen_port_;
	std::string https_listen_address_;

	size_t max_request_content_length_;
	size_t max_request_content_length() const { return max_request_content_length_; }

	class io_context_pool
	{
	public:
		io_context_pool(std::uint8_t thread_count) : thread_count_(thread_count), selected_io_context_(0)
		{
			for (std::uint8_t i = 0; i < thread_count_; ++i)
			{
				io_contexts_.emplace_back(new asio::io_context{});
				work_guards_for_io_contexts_.emplace_back(asio::make_work_guard(*io_contexts_[i]));
			}
		}

		asio::io_context& get_io_context() { return *io_contexts_[selected_io_context_++ % thread_count_].get(); }

		void run()
		{
			for (std::uint8_t i = 0; i < thread_count_; ++i)
			{
				thread_pool_.emplace_back([this, i] { io_contexts_[i]->run(); });
			}
		}

		void stop()
		{
			for (std::uint8_t i = 0; i < thread_count_; ++i)
			{
				io_contexts_[i]->stop();
				thread_pool_[i].join();
			}
		}

	private:
		size_t thread_count_;
		std::vector<std::unique_ptr<asio::io_context>> io_contexts_;
		std::vector<asio::executor_work_guard<asio::io_context::executor_type>> work_guards_for_io_contexts_;

		std::vector<std::thread> thread_pool_;
		std::atomic<size_t> selected_io_context_;
	};

	io_context_pool io_context_pool_;
	asio::steady_timer request_rate_timer_;

	asio::ip::tcp::acceptor http_acceptor_;
	asio::ip::tcp::acceptor https_acceptor_;
	asio::ssl::context https_ssl_context_;

	std::string http_this_server_base_host_;
	std::string https_this_server_base_host_;
};

} // namespace async

namespace client
{

class async_session : public std::enable_shared_from_this<async_session>
{
public:
	async_session(
		http::async::upstreams::connection_type& upstream_connection,
		std::function<void(http::response_message& response, asio::error_code& error_code)>&& on_complete)
		: upstream_connection_(upstream_connection), on_complete_(on_complete)
	{
	}

	async_session(const async_session& rhs) = default;

	async_session(async_session&& rhs) = default;

	void init_connection_to_upstream(http::request_message& request, asio::error_code& error_code)
	{
		asio::error_code error;

		write_buffer_.emplace_back(http::to_string(request));

		if (upstream_connection_.socket().is_open() == true)
		{
			char peek_buffer[1];
			upstream_connection_.socket().non_blocking(true);
			upstream_connection_.socket().receive(
				asio::buffer(peek_buffer), asio::ip::tcp::socket::message_peek, error);
			upstream_connection_.socket().non_blocking(false);
		}

		if (error != asio::error::would_block)
		{
			// connection was not open yet or closed! reopen now.
			auto me = this->shared_from_this();

			asio::error_code error_1;

			if (upstream_connection_.socket().is_open())
			{
				upstream_connection_.socket().shutdown(asio::socket_base::shutdown_send, error_1);
				upstream_connection_.socket().close(error_1);

				++upstream_connection_.owner().connections_reopened_;
			}

			upstream_connection_.resolver_.async_resolve(
				asio::ip::tcp::v4(),
				upstream_connection_.host_,
				upstream_connection_.port_,
				[me](asio::error_code error, asio::ip::tcp::resolver::iterator it) {
					if (error)
					{
						auto error_msg = error.message();
						return;
					}

					auto me_1 = me->shared_from_this();

					asio::async_connect(
						me->upstream_connection_.socket(),
						it,
						[me_1](asio::error_code error, asio::ip::tcp::resolver::iterator) {
							// TODO try next resolve result?
							if (error)
							{
								// failed
								me_1->upstream_connection_.error();
								me_1->upstream_connection_.owner().set_state(
									http::async::upstreams::upstream::state::drain);
							}
							else
							{
								me_1->write_request(error);
							}
						});
				});
		}
		else
		{
			// no need to reconnect, connection still open (due to keepalive)
			error_code.clear();
			write_request(error_code);
		}
	}

	void write_request(asio::error_code& error_code)
	{
		auto me = this->shared_from_this();

		asio::async_write(
			upstream_connection_.socket(),
			asio::buffer(write_buffer_.front()),
			[me, error_code](asio::error_code const& ec, std::size_t) {
				me->write_buffer_.pop_front();

				if (!ec)
					me->read_response_headers();
				else
					me->read_response_body_complete(error_code);
			});
	}

	void read_response_headers()
	{
		auto me = this->shared_from_this();

		upstream_connection_.buffer_.clear();

		asio::async_read_until(
			upstream_connection_.socket(),
			asio::dynamic_buffer(upstream_connection_.buffer_),
			"\r\n\r\n",
			[me](asio::error_code ec, size_t bytes_red) {
				if (!ec)
					me->read_response_headers_complete(bytes_red);
				else
					me->read_response_body_complete(ec);
			});
	}

	void read_response_headers_complete(size_t bytes_red)
	{
		http::response_parser response_parser;
		http::response_parser::result_type result;
		const char* c = nullptr;

		std::tie(result, c) = response_parser.parse(
			response_, upstream_connection_.buffer_.data(), upstream_connection_.buffer_.data() + bytes_red);

		if (result == http::response_parser::result_type::good)
		{
			auto content_length = response_.content_length();

			if (content_length > 0 && content_length != http::request_message::content_length_invalid)
			{
				auto content_already_received = static_cast<size_t>(
					upstream_connection_.buffer_.data() + upstream_connection_.buffer_.size() - c);

				response_.body().reserve(content_length);

				response_.body().assign(c, content_already_received);

				if (content_already_received < content_length)
				{
					read_response_body();
				}
				else
				{
					read_response_body_complete(asio::error_code{});
				}
			}
			else if (response_.chunked())
			{
				response_.status(http::status::internal_server_error);
				response_.body() = "chunked upstream response received\n";
				read_response_body_complete(asio::error_code{});
			}
			else
			{
				read_response_body_complete(asio::error_code{});
			}
		}
	}

	void read_response_body()
	{
		asio::error_code ec;
		if (response_.body().size() < response_.content_length())
		{
			auto me = this->shared_from_this();
			upstream_connection_.buffer_.clear();
			asio::async_read(
				upstream_connection_.socket(),
				asio::dynamic_buffer(upstream_connection_.buffer_),
				asio::transfer_at_least(1),
				[me](const asio::error_code& ec, std::size_t bytes_xfer) {
					if (!ec)
					{
						auto content_length = me->response_.content_length();

						me->response_.body().append(me->upstream_connection_.buffer_.data(), bytes_xfer);

						if (me->response_.body().length() < content_length)
						{
							me->read_response_body();
						}
						else
						{
							me->read_response_body_complete(ec);
						}
					}
					else
					{
						me->read_response_body_complete(ec);
					}
				});
		}
		else if (response_.body().size() == response_.content_length())
		{
			read_response_body_complete(ec);
		}
		else
		{
			assert(1 == 0);
			read_response_body_complete(ec);
		}
	}

	void read_response_body_complete(asio::error_code ec)
	{
		if (ec)
		{
			upstream_connection_.error();
			response_.reset();
			response_.status(http::status::service_unavailable);
			on_complete_(response_, ec);
			return;
		}
		else if (upstream_connection_.should_drain())
		{
			upstream_connection_.drain();
			on_complete_(response_, ec);
			return;
		}

		upstream_connection_.owner().update_health_check_metrics();

		on_complete_(response_, ec);
		upstream_connection_.release();
	}

private:
	http::response_message response_;
	http::async::upstreams::connection_type& upstream_connection_;
	std::deque<std::string> write_buffer_;

	std::function<void(http::response_message& response, asio::error_code& error_code)> on_complete_;
};

template <http::method::method_t method>
void async_request(
	http::async::upstreams::upstream& upstream,
	const std::string& request_url,
	const http::headers& headers,
	const std::string& body,
	std::function<void(http::response_message& response, asio::error_code& error_code)>&& on_complete)
{
	bool found = false;
	auto request = http::request_message{ method, upstream.host(), request_url, headers, body };

	do
	{
		std::unique_lock<std::mutex> connections_guard{ upstream.connection_mutex_ };
		asio::error_code error_code;

		if (upstream.state_ == http::async::upstreams::upstream::state::drain)
		{
			error_code = asio::error::connection_refused;
		}
		else
		{
			for (auto& connection : upstream.connections_)
			{
				// Select the least connected upstream
				auto expected_state = http::async::upstreams::connection_type::state::idle;

				if (connection->get_state().compare_exchange_strong(
						expected_state, http::async::upstreams::connection_type::state::waiting)
					== true)
				{
					auto selected_connection = connection.get();
					connections_guard.unlock();
					++(upstream.connections_busy_);

					std::shared_ptr<async_session> session{ new async_session(
						*selected_connection, std::move(on_complete)) };

					session->init_connection_to_upstream(request, error_code);

					if (!error_code)
						found = true;
					else
						found = false;

					break;
				}
			}
		}

		if (found == false)
		{

			if (error_code)
			{
				http::response_message response{};
				on_complete(response, error_code);
				return;
			}
			else
			{
				connections_guard.unlock();
				upstream.add_connection();
			}
		}
	} while (found == false);
}

template <http::method::method_t method>
http::response_message request(
	const std::string& request_url,
	std::string& error_code,
	const http::headers& additional_headers,
	const std::string& body = std::string{})
{
	http::response_message result;
	asio::io_context io_context;

	http::async::upstreams::upstream local_upstream(io_context, http::url::make_url(request_url).base_url(), "");

	local_upstream.set_state(http::async::upstreams::upstream::state::up);

	async_request<method>(
		local_upstream,
		http::url::make_url(request_url).target(),
		additional_headers,
		body,
		[&result, &error_code](http::response_message& response, asio::error_code& error_code_asio) {
			if (error_code_asio)
				error_code = error_code_asio.message();
			else
				result = response;
		});

	io_context.run();
	local_upstream.set_state(http::async::upstreams::upstream::state::down);

	return result;
}

template <http::method::method_t method>
void async_request(
	http::async::upstreams& upstreams,
	const std::string& base_url,
	const std::string& request_url,
	const http::headers& headers,
	const std::string& body,
	std::function<void(http::response_message& response, asio::error_code& error_code)>&& on_complete)
{
	std14::shared_lock<std14::shared_mutex> usptreams_guard{ upstreams.upstreams_lock_ };

	auto& upstream = upstreams.get_upstream(base_url);

	return async_request<method>(upstream, request_url, headers, body, std::move(on_complete));
}

template <http::method::method_t method>
void request(
	const std::string& request_url,
	const http::headers& additional_headers,
	const std::string& body,
	std::function<void(http::response_message& response, asio::error_code& error_code)>&& on_complete)
{
	asio::io_context io_context;

	http::async::upstreams::upstream local_upstream(io_context, request_url, "");

	local_upstream.set_state(http::async::upstreams::upstream::state::up);

	async_request<method>(local_upstream, request_url, additional_headers, body, std::move(on_complete));

	io_context.run();

	local_upstream.set_state(http::async::upstreams::upstream::state::down);
}

} // namespace client
} // namespace http
