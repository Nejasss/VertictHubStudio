cmake_minimum_required(VERSION 3.22.1)
project(verticthub_jni LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT "${ANDROID_ABI}" STREQUAL "arm64-v8a")
    message(FATAL_ERROR "VertictHub Studio hanya mendukung target ABI arm64-v8a (terdeteksi: ${ANDROID_ABI})")
endif()

set(PYTHON_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../python314/include/python3.14")
set(PYTHON_LIB_PATH "${CMAKE_SOURCE_DIR}/../../app/src/main/jniLibs/${ANDROID_ABI}/libpython3.14.so")

add_library(python314 SHARED IMPORTED)
set_target_properties(python314 PROPERTIES IMPORTED_LOCATION "${PYTHON_LIB_PATH}")

add_library(verticthub_jni SHARED python_bridge.cpp)

target_include_directories(verticthub_jni PRIVATE "${PYTHON_INCLUDE_DIR}")
target_link_libraries(verticthub_jni PRIVATE python314 android log)
