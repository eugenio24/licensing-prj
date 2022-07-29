cmake_minimum_required( VERSION 3.2.0 )

project( LicenseApp )

set( DEMO_NAME "LicenseApp" )
set( SDK_FOLDER_NAME "external/aws-iot-sdk" )

# Set global path variables.
get_filename_component(__root_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
set(ROOT_DIR ${__root_dir}/${SDK_FOLDER_NAME} CACHE INTERNAL "C SDK source root.")
set(DEMOS_DIR "${ROOT_DIR}/demos" CACHE INTERNAL "C SDK demos root.")
set(SYSTEM_TEST_DIR "${ROOT_DIR}/integration-test" CACHE INTERNAL "C SDK integration tests root.")
set(PLATFORM_DIR "${ROOT_DIR}/platform" CACHE INTERNAL "C SDK platform root.")
set(MODULES_DIR "${ROOT_DIR}/libraries" CACHE INTERNAL "C SDK modules root.")
set(3RDPARTY_DIR "${MODULES_DIR}/3rdparty" CACHE INTERNAL "3rdparty libraries root.")

# Set output directories.
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

# Include sdk 
include( ${CMAKE_SOURCE_DIR}/${SDK_FOLDER_NAME}/demos/logging-stack/logging.cmake )

add_subdirectory( ${MODULES_DIR} )
add_subdirectory( ${PLATFORM_DIR} )

include( ${MODULES_DIR}/standard/coreMQTT/mqttFilePaths.cmake )
include( ${MODULES_DIR}/standard/backoffAlgorithm/backoffAlgorithmFilePaths.cmake )

# Include Licensing src
include( src/licensing.cmake )

# Demo target.
add_executable(
    ${DEMO_NAME}
        "main.c"
        ${MQTT_SOURCES}
        ${MQTT_SERIALIZER_SOURCES}
        ${BACKOFF_ALGORITHM_SOURCES}
        ${LICENSING_SOURCES}
)

target_link_libraries(
    ${DEMO_NAME}
    PRIVATE
        clock_posix
        openssl_posix
)

target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        ${MQTT_INCLUDE_PUBLIC_DIRS}
        ${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}
        ${CMAKE_CURRENT_LIST_DIR}
        ${LOGGING_INCLUDE_DIRS}
        ${LICENSING_INCLUDE_DIRS}
)
