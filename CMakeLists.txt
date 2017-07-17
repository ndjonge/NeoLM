cmake_minimum_required(VERSION 3.7)

set (PROJECT_NAME "NeoLM" CXX)
project (${PROJECT_NAME})


set (BOOST_ROOT "C:\\boost_1_64_0")

find_package(Boost 1.64 REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
link_directories("C:\\boost_1_64_0\\lib64-msvc-14.1")

set (Boost_USE_MULTITHREADED ON)
set (Boost_USE_STATIC_LIBS ON)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries (${PROJECT_NAME} ${Boost_LIBRARIES})