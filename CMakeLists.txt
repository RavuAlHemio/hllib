cmake_minimum_required(VERSION 3.15)

project(HLLib
    LANGUAGES CXX C
    VERSION 2.4.6
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Compile flags specific to GCC or Clang
    add_compile_options(-Wall -fPIC)

    # Flag to make sanitized build for debug
    if (SANITIZER)
        add_compile_options(-fsanitize=address)
        add_link_options(-fsanitize=address)
    endif()

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

add_executable(hlextract
    HLExtract/Main.c
)
target_link_libraries(hlextract hl)

install(TARGETS hlextract)

