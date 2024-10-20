cmake_minimum_required(VERSION 3.5)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

project(raw2en10mb LANGUAGES C)

find_package(PCAP REQUIRED)

add_executable(${PROJECT_NAME} main.c)

target_link_libraries(${PROJECT_NAME} PCAP::PCAP)
