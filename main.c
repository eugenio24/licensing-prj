#include <stdio.h>
#include <stdlib.h>

#include "licensing.h"

int main(){

    bool validLicense = Licensing_CheckLicense();

    if(!validLicense) {
        printf("\nNO LICENSE\n");    
    }   
    
    printf("\nUNLOCKED APP");
    printf("\nEXAMPLE APP\n");
 
    return 0;
}