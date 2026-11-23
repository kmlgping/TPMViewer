cmake_minimum_required(VERSION 3.20)
project(TPMViewer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT for ALL targets (Debug -> /MTd, Release -> /MT).
# Must be set before add_library/add_executable; keeps TPMViewer and imgui
# consistent so the linker does not complain about RuntimeLibrary mismatch.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/imgui)

add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
)
target_include_directories(imgui PUBLIC ${IMGUI_DIR} ${IMGUI_DIR}/backends)
target_compile_definitions(imgui PUBLIC IMGUI_DEFINE_MATH_OPERATORS)

add_executable(TPMViewer WIN32
    src/main.cpp
    src/util.cpp
    src/hash.cpp
    src/sipa.cpp
    src/tcg_log.cpp
    src/replay.cpp
    src/tbs_api.cpp
    src/driver_report.cpp
    src/app.cpp
    src/app.rc          # 图标 + 版本信息资源（VS 生成器自动用 rc.exe 编译）
)

if(MSVC)
    target_compile_options(TPMViewer PRIVATE /utf-8 /W3)
    target_compile_options(imgui PRIVATE /utf-8)
    set_property(TARGET TPMViewer imgui PROPERTY VS_SPECTRE_MITIGATION false)
endif()

target_link_libraries(TPMViewer PRIVATE imgui d3d11 dxgi d3dcompiler dwmapi bcrypt crypt32 tbs)
