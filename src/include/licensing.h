#ifndef LICENSING_H_
#define LICENSING_H_

/************ Start of logging configuration ****************/

#include "logging_levels.h"

#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME     "LICENSING"
#endif
#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

#include "logging_stack.h"

/************ End of logging configuration ****************/

#include <stdbool.h>

/**
 * Include mqtt config
 */
#include "licensing_mqtt_config.h"

#define APP_TYPE "a-01"

bool Licensing_CheckLicense();

#endif
