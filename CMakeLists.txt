cmake_minimum_required(VERSION 3.16)
project(cliuno_drogon CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

file(GLOB SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/main.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/controllers/*.cc")

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon OpenSSL::Crypto)
