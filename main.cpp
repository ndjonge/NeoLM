#include <boost/asio.hpp>
#include <memory>
#include <chrono>
#include <iostream>
#include <thread>
#include <deque>

template <typename ConnectionHandler>
class asio_generic_server
{
	using shared_handler_t = std::shared_ptr<ConnectionHandler>;

public:
	asio_generic_server(int thread_count = 1) : thread_count(thread_count), acceptor_(io_service)
	{
	}



	void start_server(uint16_t port)
	{
		auto handler = std::make_shared<ConnectionHandler>(io_service);

		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port);
		acceptor_.open(endpoint.protocol());

		acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
		acceptor_.bind(endpoint);
		acceptor_.listen();

		acceptor_.async_accept(handler->socket(), [=](auto ec)
		{
			handle_new_connection(handler, ec);
		});

		for (auto i = 0; i < thread_count; ++i)
		{
			thread_pool.emplace_back([=] { io_service.run(); });
		}
	}



private:
	void handle_new_connection(shared_handler_t handler, boost::system::error_code const error)
	{
		if (error) { return; }

		handler->start();

		auto new_handler = std::make_shared<ConnectionHandler>(io_service);

		acceptor_.async_accept(new_handler->socket(), [=](auto ec)
		{
			handle_new_connection(new_handler, ec);
		});
	}

	int thread_count;
	std::vector<std::thread> thread_pool;
	boost::asio::io_service io_service;
	boost::asio::ip::tcp::acceptor acceptor_;
};

class chat_handler : public std::enable_shared_from_this<chat_handler>
{
public:
	chat_handler(boost::asio::io_service& service) : service_(service), socket_(service), write_strand_(service)
	{
	}

	chat_handler(chat_handler const &) = delete;
	void operator==(chat_handler const &) = delete;
	~chat_handler() = default;

	boost::asio::ip::tcp::socket& socket()
	{
		return socket_;
	}

	void start()
	{
		read_packet();
	}

	void read_packet()
	{
		boost::asio::async_read_until(socket_, in_packet_, '\n',
			[me = shared_from_this()](boost::system::error_code const& ec, std::size_t bytes_xfer)
		{
			me->read_packet_done(ec, bytes_xfer);
		});
	}

	void read_packet_done(boost::system::error_code const& error, std::size_t bytes_transferrerd)
	{
		if (error) { return; };

		std::istream stream(&in_packet_);
		std::string packet_string;

		stream >> packet_string;

		std::cout << "packet: " << packet_string << std::endl;
		boost::asio::write(socket_, boost::asio::buffer(packet_string));

		read_packet();
	}

	void send(std::string msg)
	{
		service_.post(write_strand_.wrap([&, me = shared_from_this()]()
		{
			me->queue_message(msg);
		}));
	}

	void queue_message(std::string message)
	{
		bool write_in_progress = !send_packet_queue_.empty();
		send_packet_queue_.push_back(std::move(message));

		if (!write_in_progress)
		{
			this->start_packet_send();
		}
	}

	void start_packet_send()
	{
		send_packet_queue_.front() += "\0";
		async_write(socket_, boost::asio::buffer(send_packet_queue_.front()), write_strand_.wrap([me = shared_from_this()](boost::system::error_code const& ec, std::size_t)
		{
			me->packet_send_done(ec);
		}));
	}

	void packet_send_done(boost::system::error_code const & error)
	{
		if (!error)
		{
			send_packet_queue_.pop_front();
			if (!send_packet_queue_.empty()) { this->start_packet_send(); }
		}
	}

private:
	boost::asio::io_service& service_;
	boost::asio::ip::tcp::socket socket_;
	boost::asio::io_service::strand write_strand_;
	boost::asio::streambuf in_packet_;

	std::deque<std::string> send_packet_queue_;

};

int main(int argc, char* argv[])
{

	asio_generic_server<chat_handler> server;
	server.start_server(8888);


	for (;;)
	{
	}

	return 0;
}

