#ifndef LICENSING_MQTT_CONFIG_H_
#define LICENSING_MQTT_CONFIG_H_

/**
 * @brief Details of the MQTT broker to connect to.
 */
#define AWS_IOT_ENDPOINT               "alcv3np28ivmm-ats.iot.us-east-1.amazonaws.com"

/**
 * @brief AWS IoT MQTT broker port number.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. When using port 8883, ALPN is not required.
 */
#ifndef AWS_MQTT_PORT
    #define AWS_MQTT_PORT    ( 8883 )
#endif

/**
 * @brief Path of the file containing the server's root CA certificate.
 *
 * This certificate is used to identify the AWS IoT server and is publicly
 * available. Refer to the AWS documentation available in the link below
 * https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
 *
 * @note This certificate should be PEM-encoded.
 * @note This path is relative from the demo binary created. Update
 * ROOT_CA_CERT_PATH to the absolute path if this demo is executed from elsewhere.
 */
#ifndef ROOT_CA_CERT_PATH
    #define ROOT_CA_CERT_PATH    "certificates/AmazonRootCA1.pem"
#endif

/**
 * @brief Path of the file containing the client certificate.
 *
 * @note This certificate should be PEM-encoded. 
 */
#define CLIENT_CERT_PATH    "certificates/ef99526b1858f6f802887531d94a8b8b6e52fe767cc29006857bc712d5344c85-certificate.pem.crt"

/**
 * @brief Path of the file containing the client's private key.
 *
 * @note This private key should be PEM-encoded.
 */
#define CLIENT_PRIVATE_KEY_PATH    "certificates/ef99526b1858f6f802887531d94a8b8b6e52fe767cc29006857bc712d5344c85-private.pem.key"

/**
 * @brief MQTT client identifier.
 *
 * No two clients may use the same client identifier simultaneously.
 */
#ifndef CLIENT_IDENTIFIER
    #define CLIENT_IDENTIFIER    "pi-3"
#endif

/**
 * @brief Size of the network buffer for MQTT packets.
 */
#define NETWORK_BUFFER_SIZE       ( 4096U )

/**
 * @brief The name of the operating system that the application is running on.
 * The current value is given as an example. Please update for your specific
 * operating system.
 */
#define OS_NAME                   "Ubuntu"

/**
 * @brief The version of the operating system that the application is running
 * on. The current value is given as an example. Please update for your specific
 * operating system version.
 */
#define OS_VERSION                "18.04 LTS"

/**
 * @brief The name of the hardware platform the application is running on. The
 * current value is given as an example. Please update for your specific
 * hardware platform.
 */
#define HARDWARE_PLATFORM_NAME    "PC"

/**
 * @brief The name of the MQTT library used and its version, following an "@"
 * symbol.
 */
#include "core_mqtt.h"
#define MQTT_LIB    "core-mqtt@" MQTT_LIBRARY_VERSION


#endif
