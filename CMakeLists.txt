cmake_minimum_required(VERSION 2.8)
project (MUDUODEMOSERVER)

SET (CMAKE_BUILD_TYPE "Release" )
SET (CMAKE_CXX_COMPILER g++ )
add_compile_options(-std=c++11)
#activate when SET (CMAKE_BUILD_TYPE "Release" ) -DNDEBUG option makes assert(expr) an empty operation
SET (CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -Wall -Wparentheses -finline-limit=1000 -DNDEBUG -DMUDUO_STD_STRING")
#activate when SET (CMAKE_BUILD_TYPE "Debug" )
SET (CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -o0 -Wall -Wparentheses -g2 -ggdb -DMUDUO_STD_STRING")


#add all source files

aux_source_directory(./src SRC_LIST)



#include headers  directories

include_directories(/home/$ENV{USER}/build/release-install/include)
include_directories(./include)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(/usr/include/mysql)



#link libraries directories

link_directories(/home/$ENV{USER}/build/release-install/lib)
#for libmysqlclient.so in x86
link_directories(/usr/lib/i386-linux-gnu)
#for libmysqlclient.so in x64
link_directories(/usr/lib/x86_64-linux-gnu)



#create executable binary target and link libs to it

add_executable(muduoDemoServer ${SRC_LIST})
target_link_libraries(muduoDemoServer -lmuduo_net -lmuduo_base -lmysqlclient -lpthread)



#binary executable path

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
