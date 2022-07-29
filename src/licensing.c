#include "licensing.h"

/* Standard includes. */
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* POSIX includes. */
#include <unistd.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>

/* openssl md5 */
#include <openssl/md5.h>
#define MD5_DIGEST_LENGTH_AS_STRING MD5_DIGEST_LENGTH*2+1

/**
 * @brief Given a string compute the hash
 * 
 * @param[in] str String to be hashed.
 * @param[out] digest Computed Hash.
 */
void compute_md5(char *str, unsigned char digest[16]) {
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

bool Licensing_CheckLicense(){
    char hardware_id[MD5_DIGEST_LENGTH_AS_STRING];

    LogInfo( ("Generating Hardware ID") );
    generate_HardwareId(hardware_id);


    return true;
}