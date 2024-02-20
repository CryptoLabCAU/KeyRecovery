cmake_minimum_required(VERSION 3.12)
set(NAME KEY_RECOVERY)
set(CMAKE_CXX_STANDARD 17)
project(${NAME})

find_package(OpenSSL REQUIRED)

include_directories(include)

set(COMMON_SOURCES
    src/parties.cpp
    src/utils.cpp
)

set(HJKY_SOURCES
    src/HJKY_recovery.cpp
)

set(OURS_SOURCES
    src/our_recovery.cpp
)

add_executable(HJKY_RECOVERY ${COMMON_SOURCES} ${HJKY_SOURCES})

add_executable(OUR_RECOVERY ${COMMON_SOURCES} ${OURS_SOURCES})

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(.)

target_link_libraries(HJKY_RECOVERY PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(OUR_RECOVERY PRIVATE ${OPENSSL_LIBRARIES})