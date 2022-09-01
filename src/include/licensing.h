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

#define APP_TYPE "a-01"

#define LICENSE_FOLDER_NAME "license/"
#define LICENSE_FILE_NAME "license.txt"
#define SIGNATURE_FILE_NAME "signature.bin"

#define SIGNATURE_LENGTH 256

bool Licensing_CheckLicense();

#endif
