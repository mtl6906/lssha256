project(lssha256)

cmake_minimum_required(VERSION 3.10)

add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)

aux_source_directory(src/ls SRC)

aux_source_directory(sample SRC_SAMPLE)

include_directories(include)

link_directories(/usr/local/lib)

add_library(lssha256 SHARED ${SRC})

add_executable(testcase ${SRC} ${SRC_SAMPLE})

install(TARGETS lssha256 DESTINATION lib)
install(DIRECTORY include/ls DESTINATION include)
