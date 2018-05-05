cmake_minimum_required(VERSION 3.8)

set (PROJECT_NAME "NeoLM" CXX)
project (${PROJECT_NAME})

set (CMAKE_C_COMPILER "clang")

IF (WIN32)
	set (BOOST_ROOT "C:/Development Libraries/boost_1_64_0")
	set (BOOST_LIBRARYDIR "C:/Development Libraries/boost_1_64_0/lib64-msvc-14.1")
	set (OPENSSL_ROOT_DIR "C:/Development Libraries/openssl-bld-lib/")
	link_directories("C:/Development Libraries/boost_1_64_0/lib64-msvc-14.1")
	add_definitions(-DWINVER=0x502
                    -D_WIN32_WINNT=0x502
                    -D_WIN32_WINDOWS=0x502
                    -D_SETUPAPI_VER=0x502
#					-DBOOST_ASIO_ENABLE_HANDLER_TRACKING
					-D_USE_NO_REGEX
	)
	set (Boost_USE_STATIC_LIBS ON)
ELSE()
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set( BOOST_ROOT "/home/ndjonge/boost_1_64_0" CACHE PATH "Boost library path" )
    set( BOOST_NO_SYSTEM_PATHS on CACHE BOOL "Do not search system for Boost" )
    set( BOOST_INCLUDEDIR "/home/ndjonge/boost_1_64/include")
    set (OPENSSL_ROOT_DIR "~/openssl-dev")
	set (Boost_USE_STATIC_LIBS OFF)
ENDIF()


set (Boost_USE_MULTITHREADED ON)

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)


find_package(Boost 1.64 REQUIRED system thread)
find_package(OpenSSL REQUIRED)

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries (${PROJECT_NAME} ${Boost_LIBRARIES})
target_link_libraries( ${PROJECT_NAME} ${OPENSSL_LIBRARIES})
