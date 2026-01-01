cmake_minimum_required(VERSION 3.22.1)

project("app_fortress_native")

# Security hardening flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -fvisibility=hidden -fstack-protector-strong")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s -fomit-frame-pointer -O3")

# Position-independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Create the native library
add_library(
    app_fortress_native
    SHARED
    app_fortress_native.c
)

# Link required libraries
target_link_libraries(
    app_fortress_native
    android
    log
    dl
)

# Hide symbols
set_target_properties(
    app_fortress_native
    PROPERTIES
    C_VISIBILITY_PRESET hidden
)
