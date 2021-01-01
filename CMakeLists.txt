# cmake_minimum_required (VERSION 3.0)
# project (emp-ot)
# set(NAME "emp-ot")

# add_definitions(-Wfatal-errors)

# set(CMAKE_CXX_STANDARD 20)

# find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
# include(${CMAKE_FOLDER}/cmake/common.cmake)
# include(${CMAKE_FOLDER}/cmake/enable_rdseed.cmake)
# include(${CMAKE_FOLDER}/cmake/enable_float.cmake)

# find_package(emp-tool REQUIRED)
# include_directories(${EMP-TOOL_INCLUDE_DIRS})

# # Installation
# install(FILES cmake/emp-ot-config.cmake DESTINATION cmake/)
# install(DIRECTORY emp-ot DESTINATION include/)

# macro (add_test _name)
#   add_test_with_lib(${_name} ${EMP-TOOL_LIBRARIES})
# endmacro()

# add_test(ot)
cmake_minimum_required (VERSION 3.10)
project (Harp)
set(NAME "Harp")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()


add_definitions(-Wfatal-errors)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-pthread -Wall -march=native -O3 -maes -mrdseed")

find_package(OpenSSL REQUIRED)
find_package(emp-tool REQUIRED)


set(sources
  src/base.cc
  src/point.cc)


add_library(Harp ${sources})
target_include_directories(Harp PUBLIC src ${EMP-TOOL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(Harp ${EMP-TOOL_LIBRARY} ${OPENSSL_LIBRARIES})


add_executable(HarpTest test/ot.cc)
target_include_directories(
  HarpTest
  PUBLIC
  src
  ${EMP-TOOL_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR})
target_link_libraries(
  HarpTest
  Harp
  ${EMP-TOOL_LIBRARY}
  ${OPENSSL_LIBRARIES})
