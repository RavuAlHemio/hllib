cmake_minimum_required(VERSION 3.15)

project(HLLib
    LANGUAGES CXX C
    VERSION 2.4.6
)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
add_compile_options(-Wall -fPIC)

if( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" )
    add_compile_options(-g)
endif()
if( "${CMAKE_BUILD_TYPE}" STREQUAL "Release" )
    add_compile_options(-O3)
endif()

# Flag to make sanitized build for debug
if (SANITIZER)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

include_directories(
    HLLib/
    HLExtract/
    lib/
)

add_library(hl STATIC
    HLLib/BSPFile.cpp
    HLLib/Checksum.cpp
    HLLib/DebugMemory.cpp
    HLLib/DirectoryFile.cpp
    HLLib/DirectoryFolder.cpp
    HLLib/DirectoryItem.cpp
    HLLib/Error.cpp
    HLLib/FileMapping.cpp
    HLLib/FileStream.cpp
    HLLib/GCFFile.cpp
    HLLib/GCFStream.cpp
    HLLib/HLLib.cpp
    HLLib/Mapping.cpp
    HLLib/MappingStream.cpp
    HLLib/MemoryMapping.cpp
    HLLib/MemoryStream.cpp
    HLLib/NCFFile.cpp
    HLLib/NullStream.cpp
    HLLib/PAKFile.cpp
    HLLib/Package.cpp
    HLLib/ProcStream.cpp
    HLLib/SGAFile.cpp
    HLLib/Stream.cpp
    HLLib/StreamMapping.cpp
    HLLib/Utility.cpp
    HLLib/VBSPFile.cpp
    HLLib/VPKFile.cpp
    HLLib/WADFile.cpp
    HLLib/Wrapper.cpp
    HLLib/XZPFile.cpp
    HLLib/ZIPFile.cpp
)

target_compile_options(hl PUBLIC
    -fvisibility=hidden
)

add_executable(hlextract
    HLExtract/Main.c
)
target_link_libraries(hlextract hl)

install(TARGETS hlextract)
