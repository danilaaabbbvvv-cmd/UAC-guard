cmake_minimum_required(VERSION 3.10)
project(UACGuard)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(UACGuard UACGuard.cpp)
    target_link_libraries(UACGuard
        advapi32
        user32
        wevtapi
    )
    set_target_properties(UACGuard PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
else()
    message(FATAL_ERROR "UACGuard поддерживает только Windows.")
endif()

# Статическая линковка для MinGW
if(MINGW)
    set_target_properties(UACGuard PROPERTIES
        LINK_FLAGS "-static"
    )
endif()