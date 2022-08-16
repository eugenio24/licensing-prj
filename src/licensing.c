#define _XOPEN_SOURCE // for strptime

#include "licensing.h"
#include "mqtt_handler.h"

/* Standard includes. */
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>

/* openssl */
#include <openssl/md5.h>
#define MD5_DIGEST_LENGTH_AS_STRING MD5_DIGEST_LENGTH*2+1
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "base64_utils.h"

#define MAX_FILE_LEN 100

struct parsedLicense_t {
    char* app_type;
    char* license_key;
    char* hardware_id;
    char* expiration;
};

/**
 * @brief Given a string compute the hash
 * 
 * @param[in] str String to be hashed.
 * @param[out] digest Computed Hash.
 */
void compute_md5(char *str, unsigned char digest[MD5_DIGEST_LENGTH]){
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, str, strlen(str));
    MD5_Final(digest, &ctx);
}

void compute_sha256(char *str, unsigned char digest[SHA256_DIGEST_LENGTH]){
    SHA256_CTX ctx;
    SHA256_Init(&ctx);    
    SHA256_Update(&ctx, str, strlen(str));
    SHA256_Final(digest, &ctx);
}

/**
 * @brief Returns a string with all the MACs concatenated
 */
int getMACs(char** mac_concat){
    *mac_concat = NULL;

    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;    

    if (getifaddrs(&ifaddr) < 0) {
        LogError( ("Error while retriving MAC address.") );        
        return EXIT_FAILURE;
    }else{
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {            
            if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) ) {                
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;                           
                bool isValid = false;
                char mac_str[18] = {0};

                if(s->sll_halen == 6) { // check MAC len
                    int i = 0;
                    for (i=0; i < s->sll_halen; i++) {
                        if(s->sll_addr[i] != 0) isValid = true;                        
                        sprintf(mac_str+strlen(mac_str), "%02x%c", s->sll_addr[i], (i+1 != s->sll_halen) ?':':'\0');                
                    }
                }

                if(isValid){                    
                    size_t mac_len = strlen(mac_str);                    
                    size_t concat_len = strlen(*mac_concat != NULL ? *mac_concat : "");              
                    
                    char* p = realloc(*mac_concat, concat_len+mac_len+1);                    
                    if(!p){
                        LogError( ("Out of memory.") );                        
                        free(*mac_concat);
                        return EXIT_FAILURE;        
                    }

                    *mac_concat = p;                    
                    (*mac_concat)[concat_len] = '\0';                    
                    strcat(*mac_concat, mac_str);                                        
                }                
            }
        }
        
        freeifaddrs(ifaddr);
    }
    
    return EXIT_SUCCESS;
}

/**
 * @brief Hash the concatenation of all the MACs
 * 
 * @param[out] mac_hash The MACs hash string.
 */
int hashMACs(char* mac_hash){
    char* mac_concat;
    int result = getMACs(&mac_concat);
    if(result == EXIT_SUCCESS){        
        unsigned char digest[16];
        compute_md5(mac_concat, digest);
        free(mac_concat);

        // hash to string
        for (int i = 0, j = 0; i < 16; i++, j+=2)
            sprintf(mac_hash+j, "%02x", digest[i]);
        mac_hash[sizeof digest * 2] = 0;
    }
    return result;
}

/**
 * @brief Generates an Hardware ID
 * 
 * @param[out] hardware_id The Hardware ID 
 */
int generate_HardwareId(char* hardware_id){    
    char mac_hash[MD5_DIGEST_LENGTH_AS_STRING];
    int result = hashMACs(mac_hash);
    
    if(result == EXIT_SUCCESS){
        strcpy(hardware_id, mac_hash);
    }

    return result;
}

/**
 * @brief Return License and Signature File Paths
 * 
 * 
 */
void getFilesPaths(char** license, char** signature){
    /* TODO this should depend on the specific app */
    const char* BASE_FOLDER = "./";

    size_t lic_path_len =  strlen(BASE_FOLDER) + strlen(LICENSE_FOLDER_NAME) + strlen(LICENSE_FILE_NAME) +1;
    size_t sig_path_len =  strlen(BASE_FOLDER) + strlen(LICENSE_FOLDER_NAME) + strlen(LICENSE_FILE_NAME) +1;
    char* LICENSE_FILE_PATH = malloc(sizeof(char) *lic_path_len);
    char* SIGNATURE_FILE_PATH = malloc(sizeof(char) *sig_path_len);
    LICENSE_FILE_PATH[0] = '\0';
    SIGNATURE_FILE_PATH[0] = '\0';

    strcat(LICENSE_FILE_PATH, BASE_FOLDER);
    strcat(SIGNATURE_FILE_PATH, BASE_FOLDER);
    strcat(LICENSE_FILE_PATH, LICENSE_FOLDER_NAME);
    strcat(SIGNATURE_FILE_PATH, LICENSE_FOLDER_NAME);
    strcat(LICENSE_FILE_PATH, LICENSE_FILE_NAME);
    strcat(SIGNATURE_FILE_PATH, SIGNATURE_FILE_NAME);

    *license = LICENSE_FILE_PATH;
    *signature = SIGNATURE_FILE_PATH;
}

/**
 * @brief check if it's the first start, to do it check if the license file already exists, 
 * if not, create the folder in which the license received from the server will then be saved. 
 */
int checkFirstStartUp(char* LICENSE_FILE_PATH, bool* firstStartup){
    *firstStartup = false;

    if(access(LICENSE_FILE_PATH, R_OK | W_OK) < 0) {
        if(errno == ENOENT){
            LogInfo( ("No license file found.") );
            *firstStartup = true;

            size_t lic_dir_path_len = strlen(LICENSE_FILE_PATH) - strlen(LICENSE_FILE_NAME)+1;
            char lic_dir_path[lic_dir_path_len];
            strcpy(lic_dir_path, LICENSE_FILE_PATH);
            lic_dir_path[lic_dir_path_len-1] = '\0';
            
            if(mkdir(lic_dir_path, S_IRWXU) < 0){
                if(errno != EEXIST){                                                            
                    LogError( ("Cannot create License folder: %s", strerror(errno)) );        
                    return EXIT_FAILURE;
                }
            }
        }else{            
            LogError( ("Cannot create License File: %s", strerror(errno)) );        
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int saveLicense(int license_fd, char* license, int signature_fd, char* signature){
    size_t l_len = strlen(license);
    char l_buffer[l_len+2];
    sprintf(l_buffer, "%s\n", license);
    
    if(write(license_fd, l_buffer, l_len+1) < 0){
        LogError(("Error while writing license file: %s", strerror(errno)));        
        return EXIT_FAILURE;
    }

    if(write(signature_fd, signature, SIGNATURE_LENGTH) < 0){
        LogError(("Error while writing signature license file: %s", strerror(errno)));        
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int activateLicense(char* hw_id, char* app_type, char** license, unsigned char** signature){
    int status = sendActivation(hw_id, app_type);
    if(status == EXIT_FAILURE){
        LogError( ("Cannot get License.") );        
        return EXIT_FAILURE;
    }

    char* sign;
    int statusLicense = getLicense(license);
    int statusSignature = getSignature(&sign);

    if(statusLicense == EXIT_FAILURE || statusSignature == EXIT_FAILURE){
        LogError( ("Cannot get License.") );    
        return EXIT_FAILURE;
    }else{
        size_t decode_size = strlen(sign);
        size_t out_size;
        *signature = base64_decode(sign, decode_size, &out_size);
        
        free(sign);
        if(out_size != SIGNATURE_LENGTH){
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int renewLicense(char* hw_id, char* app_type, char* license_key, char** license, unsigned char** signature){
    int status = sendRenew(license_key, hw_id, app_type);
    if(status == EXIT_FAILURE){
        LogError( ("Cannot renew License.") );        
        return EXIT_FAILURE;
    }

    char* sign;
    int statusLicense = getLicense(license);
    int statusSignature = getSignature(&sign);

    if(statusLicense == EXIT_FAILURE || statusSignature == EXIT_FAILURE){
        LogError( ("Cannot get License.") );    
        return EXIT_FAILURE;
    }else{
        size_t decode_size = strlen(sign);
        size_t out_size;
        *signature = base64_decode(sign, decode_size, &out_size);

        free(sign);
        if(out_size != SIGNATURE_LENGTH){
            return EXIT_FAILURE;
        }
    }
    
    return EXIT_SUCCESS;
}

int parseLicense(char* license, struct parsedLicense_t* pParsedLicense){
    char* license_key = strtok(license, ";");
    char* hardware_id = strtok(NULL, ";");
    char* app_type = strtok(NULL, ";");
    char* expiration = strtok(NULL, "\n");

    size_t license_key_len = strlen(license_key);
    size_t hardware_id_len = strlen(hardware_id);
    size_t app_type_len = strlen(app_type);
    size_t expiration_len = strlen(expiration);

    if(license_key_len <= 0 || hardware_id_len <= 0 || app_type_len <= 0 || expiration_len <= 0){
        LogError(("Error parsing license file."));
        return EXIT_FAILURE;
    }

    pParsedLicense->license_key = malloc(sizeof(char)*(license_key_len+1));
    pParsedLicense->license_key[0] = '\0';
    strcpy(pParsedLicense->license_key, license_key);

    pParsedLicense->hardware_id = malloc(sizeof(char)*(hardware_id_len+1));
    pParsedLicense->hardware_id[0] = '\0';
    strcpy(pParsedLicense->hardware_id, hardware_id);

    pParsedLicense->app_type = malloc(sizeof(char)*(app_type_len+1));
    pParsedLicense->app_type[0] = '\0';
    strcpy(pParsedLicense->app_type, app_type);

    pParsedLicense->expiration = malloc(sizeof(char)*(expiration_len+1));
    pParsedLicense->expiration[0] = '\0';
    strcpy(pParsedLicense->expiration, expiration);

    return EXIT_SUCCESS;
}

int verifySignature(char* license, unsigned char* signature){    
    unsigned char digest[SHA256_DIGEST_LENGTH];    
    compute_sha256(license, digest);

    FILE* pubkey = fopen("./certificates/public.pem", "r"); 
 
    RSA* rsa_pubkey = PEM_read_RSA_PUBKEY(pubkey, NULL, NULL, NULL);
 
    int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH,
                            signature, SIGNATURE_LENGTH, rsa_pubkey);
    RSA_free(rsa_pubkey);
    fclose(pubkey);
 
    if(result == 1){
        LogInfo(("Signature is valid."));
        return EXIT_SUCCESS;
    }else{
        LogError(("Signature is Invalid."));
        return EXIT_FAILURE;
    }
}

bool isExpiredLicense(char* expiration){
    time_t current_time = time(NULL);

    if (current_time == ((time_t)-1)) {
        LogError(("Error obtaining current time."));
        return true;
    }

    struct tm expiration_tm;
    char *s = strptime(expiration, "%Y-%m-%d %H:%M:%S.", &expiration_tm);
    if(s == NULL){
        LogError(("Error parsing expiration date."));
        return true;
    }

    time_t expiration_time = mktime(&expiration_tm);

    double diff = difftime(expiration_time, current_time);
    if(diff > 0){        
        return false;
    }else{        
        return true;
    }
}

bool checkLicense(struct parsedLicense_t* pParsedLicense, char* hw_id, char* app_type){
    if(strcmp(pParsedLicense->hardware_id, hw_id) != 0){
        return false;
    }
    if(strcmp(pParsedLicense->app_type, app_type) != 0){
        return false;
    }
    return true;
}

bool Licensing_CheckLicense(){
    bool validLicense = false;
    int result;
    char* LICENSE_FILE_PATH;
    char* SIGNATURE_FILE_PATH;
    getFilesPaths(&LICENSE_FILE_PATH, &SIGNATURE_FILE_PATH);

    bool firstStartup;
    result = checkFirstStartUp(LICENSE_FILE_PATH, &firstStartup);
    if(result == EXIT_FAILURE){
        free(LICENSE_FILE_PATH);
        free(SIGNATURE_FILE_PATH);
        return false;
    }

    char* license;
    unsigned char* signature;

    LogInfo( ("Generating Hardware ID") );
    char hardware_id[MD5_DIGEST_LENGTH_AS_STRING];    
    result = generate_HardwareId(hardware_id);    
    if(result == EXIT_FAILURE){
        free(LICENSE_FILE_PATH);
        free(SIGNATURE_FILE_PATH);
        return false;
    }

    int license_file = -1;
    int signature_file = -1;

    if(firstStartup) {
        LogInfo(("Obtaining a license."));
        result = activateLicense(hardware_id, APP_TYPE, &license, &signature);
        if(result == EXIT_FAILURE){
            return false;
        }

        LogInfo(("Saving License."));
        
        license_file = open(LICENSE_FILE_PATH, O_CREAT | O_RDWR, 0700);
        if(license_file < 0){
            LogError(("Error while creating license file: %s", strerror(errno)));        
            return false;
        }

        signature_file = open(SIGNATURE_FILE_PATH, O_CREAT | O_RDWR, 0700);
        if(signature_file < 0){
            LogError(("Error while creating license file: %s", strerror(errno)));        
            return false;
        }

        result = saveLicense(license_file, license, signature_file, signature);
        if(result == EXIT_FAILURE){ 
            free(LICENSE_FILE_PATH);
            free(SIGNATURE_FILE_PATH);
            free(license);
            free(signature);
            return false;
        }
    }else{
        license_file = open(LICENSE_FILE_PATH, O_RDWR, 0700);
        if(license_file < 0){
            LogError(("Error while opening license file: %s", strerror(errno)));        
            return false;
        }

        signature_file = open(SIGNATURE_FILE_PATH, O_RDWR, 0700);
        if(signature_file < 0){
            LogError(("Error while opening signature file: %s", strerror(errno)));        
            return false;
        }

        LogInfo(("Reading License."));

        char buffer[MAX_FILE_LEN] = {0};

        int r = read(license_file, buffer, MAX_FILE_LEN);
        if(r < 0){
            free(LICENSE_FILE_PATH);
            free(SIGNATURE_FILE_PATH);
            LogError(("Error while reading license file: %s", strerror(errno)));
            return false;
        }

        buffer[strcspn(buffer, "\r\n")] = 0;
        
        license = malloc(sizeof(char) * (strlen(buffer)+1));
        license[0] = '\0';
        strcpy(license, buffer);

        signature = malloc(SIGNATURE_LENGTH);
        int s = read(signature_file, signature, SIGNATURE_LENGTH);
        if(s < 0){
            free(LICENSE_FILE_PATH);
            free(SIGNATURE_FILE_PATH);
            LogError(("Error while reading license signature file: %s", strerror(errno)));
            return false;
        }
    }

    LogInfo(("Verifing signature."));
    result = verifySignature(license, signature);
    if(result == EXIT_FAILURE){
        return false;
    }
    
    struct parsedLicense_t parsedLicense;
    result = parseLicense(license, &parsedLicense);
    if(result == EXIT_SUCCESS){
        bool expired = isExpiredLicense(parsedLicense.expiration);
        if(expired){
            LogInfo(("License Expired. Sending Renew..."));
            result = renewLicense(hardware_id, APP_TYPE, parsedLicense.license_key, &license, &signature);
            if(result == EXIT_FAILURE){ 
                free(parsedLicense.license_key);
                free(parsedLicense.app_type);
                free(parsedLicense.hardware_id);
                free(parsedLicense.expiration);

                free(LICENSE_FILE_PATH);
                free(SIGNATURE_FILE_PATH);
                free(license);
                free(signature);
                return false;
            }

            result = saveLicense(license_file, license, signature_file, signature);
            if(result == EXIT_FAILURE){
                free(parsedLicense.license_key);
                free(parsedLicense.app_type);
                free(parsedLicense.hardware_id);
                free(parsedLicense.expiration);

                free(LICENSE_FILE_PATH);
                free(SIGNATURE_FILE_PATH);
                free(license);
                free(signature);
                return false;
            }

            // verify the signature of the new license
            result = verifySignature(license, signature);
            if(result == EXIT_FAILURE){
                return false;
            }
            
            // parse the new license and check expiration
            result = parseLicense(license, &parsedLicense);
            if(result == EXIT_FAILURE){
                return false;
            }
            
            expired = isExpiredLicense(parsedLicense.expiration);
            if(expired){
                return false;
            }
        }

        validLicense = checkLicense(&parsedLicense, hardware_id, APP_TYPE);
        if(!validLicense){
            LogError(("Invalid License."));
        }else{
            LogInfo(("Valid License."));
        }
    }else{
        LogError(("Error parsing license."));
        return false;
    }

    free(parsedLicense.license_key);
    free(parsedLicense.app_type);
    free(parsedLicense.hardware_id);
    free(parsedLicense.expiration);

    free(LICENSE_FILE_PATH);
    free(license);
    return validLicense;
}
