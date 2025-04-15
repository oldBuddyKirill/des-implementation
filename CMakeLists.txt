cmake_minimum_required(VERSION 3.28)

project(des_implementation)

set(CMAKE_CXX_STANDARD 14)

add_executable(
${PROJECT_NAME}
    main.cpp
    tables.h
    utils.h
)
