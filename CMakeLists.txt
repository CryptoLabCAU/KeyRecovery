cmake_minimum_required(VERSION 3.12)
set(NAME KEY_RECOVERY)
set(CMAKE_CXX_STANDARD 17)
project(${NAME})

# OpenSSL 패키지 찾기
find_package(OpenSSL REQUIRED)

# 소스 파일을 포함하는 디렉토리 설정
include_directories(include)

# 공통 헤더 파일 목록
set(COMMON_SOURCES
    src/parties.cpp
    src/utils.cpp
)

# HJKY.cpp 소스 파일 목록
set(HJKY_SOURCES
    src/HJKY_recovery.cpp
)

# ours.cpp 소스 파일 목록
set(OURS_SOURCES
    src/our_recovery.cpp
)

# HJKY 실행 파일 빌드
add_executable(HJKY_RECOVERY ${COMMON_SOURCES} ${HJKY_SOURCES})

# ours 실행 파일 빌드
add_executable(OUR_RECOVERY ${COMMON_SOURCES} ${OURS_SOURCES})

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# OpenSSL 라이브러리 링크
include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(.)

target_link_libraries(HJKY_RECOVERY PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(OUR_RECOVERY PRIVATE ${OPENSSL_LIBRARIES})