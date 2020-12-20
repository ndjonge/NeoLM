#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <numeric>
#include <unordered_map>
#include <vector>

#include "http_basic.h"

//#include "http_asio.h"
//#include "neolm.h"


#include "cld_director.h"

template <typename T, std::uint8_t S, typename Tacc = std::make_unsigned_t<T>> class moving_average
{
public:
	moving_average(T initial = T{ 0 }) : accumulator_((static_cast<Tacc>( initial ) << S) - initial) {}

	T operator()(T input)
	{
		accumulator_ += static_cast<Tacc>(input);
		Tacc output = (accumulator_ + half) >> S;
		accumulator_ -= output;

		return static_cast<T>(output);
	}

	constexpr static Tacc max = (std::numeric_limits<Tacc>::max)();
	constexpr static Tacc min = (std::numeric_limits<Tacc>::min)();
	constexpr static Tacc half = 1 << (S - 1);;

private:
	Tacc accumulator_;
};

int main(int argc, const char* argv[])
{

	moving_average<std::uint16_t, 0> load{ 100 };

	std::cout << std::int16_t(load(100)) << "\r";

	network::init();
	network::ssl::init();

	exit(0);

	http::client::request<http::method::get>(
		"http://nlbalcc/",
		{},
		"",
		[](http::response_message& response, asio::error_code& ec) 
		{
			if (!ec)
				std::cout << "body:" << response.body() << "\n";
		}
	);

	start_cld_manager_server(argc, argv);

	while (1)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}
