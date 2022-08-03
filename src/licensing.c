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

/* openssl md5 */
#include <openssl/md5.h>
#define MD5_DIGEST_LENGTH_AS_STRING MD5_DIGEST_LENGTH*2+1

#define MAX_FILE_LEN 100

/**
 * @brief Given a string compute the hash
 * 
 * @param[in] str String to be hashed.
 * @param[out] digest Computed Hash.
 */
void compute_md5(char *str, unsigned char digest[16]){
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, str, strlen(str));
    MD5_Final(digest, &ctx);
}

/**
 * @brief Returns a string with all the MACs concatenated
 * 
 * @return The concatenated string of MACs.
 */
char* getMACs(){
    char* mac_concat = NULL;

    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;    

    if (getifaddrs(&ifaddr) < 0) {
        LogError( ("Error while retriving MAC address.") );        
        exit(EXIT_FAILURE);
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
                    size_t concat_len = strlen(mac_concat != NULL ? mac_concat : "");              
                    
                    char* p = realloc(mac_concat, concat_len+mac_len+1);
                    if(!p){
                        LogError( ("Out of memory.") );                        
                        free(mac_concat);
                        exit(EXIT_FAILURE);        
                    }

                    mac_concat = p;
                    mac_concat[concat_len] = '\0';
                    strcat(mac_concat, mac_str);
                }
            }
        }

        freeifaddrs(ifaddr);
    }
    
    return mac_concat;
}

/**
 * @brief Hash the concatenation of all the MACs
 * 
 * @param[out] mac_hash The MACs hash string.
 */
void hashMACs(char* mac_hash){
    char* mac_concat = getMACs();

    unsigned char digest[16];
    compute_md5(mac_concat, digest);
    free(mac_concat);

    // hash to string
    for (int i = 0, j = 0; i < 16; i++, j+=2)
        sprintf(mac_hash+j, "%02x", digest[i]);
    mac_hash[sizeof digest * 2] = 0;
}

/**
 * @brief Generates an Hardware ID
 * 
 * @param[out] hardware_id The Hardware ID 
 */
void generate_HardwareId(char* hardware_id){
    char mac_hash[MD5_DIGEST_LENGTH_AS_STRING];
    hashMACs(mac_hash);

    /* TODO add something else besides the mac */
    strcpy(hardware_id, mac_hash);
}

/**
 * @brief Return License File Path
 * 
 * @return The License File path.
 */
char* getLicensePath(){
    /* TODO this should depend on the specific app */
    const char* BASE_FOLDER = "./";

    size_t lic_path_len =  strlen(BASE_FOLDER) + strlen(LICENSE_FOLDER_NAME) + strlen(LICENSE_FILE_NAME) +1;
    char* LICENSE_FILE_PATH = malloc(sizeof(char) *lic_path_len);
    LICENSE_FILE_PATH[0] = '\0';
    strcat(LICENSE_FILE_PATH, BASE_FOLDER);
    strcat(LICENSE_FILE_PATH, LICENSE_FOLDER_NAME);
    strcat(LICENSE_FILE_PATH, LICENSE_FILE_NAME);

    return LICENSE_FILE_PATH;
}

/**
 * @brief check if it's the first start, to do it check if the license file already exists, 
 * if not, create the folder in which the license received from the server will then be saved.
 * 
 * @return true if firstStartup
 */
bool checkFirstStartUp(char* LICENSE_FILE_PATH){
    bool firstStartup = false;

    if(access(LICENSE_FILE_PATH, R_OK | W_OK) < 0) {
        if(errno == ENOENT){
            LogInfo( ("No license file found.") );
            firstStartup = true;

            size_t lic_dir_path_len = strlen(LICENSE_FILE_PATH) - strlen(LICENSE_FILE_NAME)+1;
            char lic_dir_path[lic_dir_path_len];
            strcpy(lic_dir_path, LICENSE_FILE_PATH);
            lic_dir_path[lic_dir_path_len-1] = '\0';
            
            if(mkdir(lic_dir_path, S_IRWXU) < 0){
                if(errno != EEXIST){                                        
                    free(LICENSE_FILE_PATH);
                    LogError( ("Cannot create License folder: %s", strerror(errno)) );        
                    exit(EXIT_FAILURE);
                }
            }
        }else{
            free(LICENSE_FILE_PATH);
            LogError( ("Cannot create License File: %s", strerror(errno)) );        
            exit(EXIT_FAILURE);
        }
    }

    return firstStartup;
}

char* activateLicense(char* hw_id, char* app_type){
    int status = sendActivation(hw_id, app_type);
    if(status == EXIT_FAILURE){
        LogError( ("Cannot get License.") );        
        exit(EXIT_FAILURE);
    }

    return getLicense();    
}

bool checkLicense(char* license, char* hw_id){
    int status = sendCheck(license, hw_id);
    if(status == EXIT_FAILURE){
        LogError( ("Error validating License.") );        
        exit(EXIT_FAILURE);
    }
    
    return isValidLicense();
}

bool Licensing_CheckLicense(){
    char* LICENSE_FILE_PATH = getLicensePath();
    bool firstStartup = checkFirstStartUp(LICENSE_FILE_PATH);
    char* license;

    LogInfo( ("Generating Hardware ID") );
    char hardware_id[MD5_DIGEST_LENGTH_AS_STRING];
    generate_HardwareId(hardware_id);    


    int license_file = open(LICENSE_FILE_PATH, O_CREAT | O_RDWR, 0700);
    if(license_file < 0){
        LogError(("Error while opening/creating license file: %s", strerror(errno)));        
        return false;
    }

    if(firstStartup) {
        LogInfo(("Obtaining a license."));
        license = activateLicense(hardware_id, APP_TYPE);

        LogInfo(("Saving License."));

        size_t l_len = strlen(license);
        char buffer[l_len+2];
        sprintf(buffer, "%s\n", license);

        if(write(license_file, buffer, strlen(buffer)) < 0){
            free(LICENSE_FILE_PATH);
            free(license);
            LogError(("Error while writing license file: %s", strerror(errno)));        
            return false;
        }
    }else{
        LogInfo(("Reading License."));

        char buffer[MAX_FILE_LEN] = {0};

        int r = read(license_file, buffer, MAX_FILE_LEN);
        if(r < 0){
            free(LICENSE_FILE_PATH);
            LogError(("Error while reading license file: %s", strerror(errno)));
            return false;
        }

        buffer[strcspn(buffer, "\r\n")] = 0;
        
        license = malloc(sizeof(char) * (strlen(buffer)+1));
        license[0] = '\0';
        strcpy(license, buffer);
    }

    // check license
    bool licenseCheck = checkLicense(license, hardware_id);

    free(LICENSE_FILE_PATH);
    free(license);
    return licenseCheck;
}

