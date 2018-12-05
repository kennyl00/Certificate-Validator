#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/buffer.h>

#define TRUE 1
#define FALSE 0
#define NEG -1
#define BUFSIZE 1024
#define MIN_KEY_LEN 2048

#define SAN "X509v3 Subject Alternative Name"
#define BC "X509v3 Basic Constraints"
#define SKI "X509v3 Subject Key Identifier"
#define AKI "X509v3 Authority Key Identifier"
#define KU "X509v3 Key Usage"
#define EKU "X509v3 Extended Key Usage"

#define CONSTRAINTS "CA:FALSE"
#define USAGE "TLS Web Server Authentication"

/* Record down the results on the output file */
int record(char* cert, char* url, int valid, const char *filename){
    FILE *fp;

    fp = fopen(filename, "a");

    if(!fp){
        printf("ERROR in opening/creating outputfile.csv!\n");
        exit(EXIT_FAILURE);
    }

    if(!(fprintf(fp, "%s,%s,%d\n",cert,url,valid))){
        printf("ERROR in writing to outputfile.csv!\n");
        exit(EXIT_FAILURE);
    }

    fclose(fp);

    return 0;
}


/* Validate Current Date in between NOT BEFORE and NOT AFTER date */
int valid_DATE(X509 *cert){
    /* Pointers to Day and Sec for Before and After date*/
    int *pbday;
    int *pbsec;
    int *paday;
    int *pasec;
    pbday = malloc(sizeof(int));
    pbsec = malloc(sizeof(int));
    paday = malloc(sizeof(int));
    pasec = malloc(sizeof(int));

    if(!pbday || !pbsec || !paday || !pasec){
        printf("ERROR in memory allocation for pday and psec!\n");
        exit(EXIT_FAILURE);
    }

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    ASN1_TIME_diff(pbday, pbsec, not_before, NULL);
    ASN1_TIME_diff(paday, pasec, not_after, NULL);

    int flag = FALSE;

    /* Valid if BEFORE day/sec == POSITIVE && AFTER day/sec == NEGATIVE */
    if((*pbday > 0 || *pbsec > 0) && (*paday < 0 || *pasec < 0)){
        flag = TRUE;
    }

    free(pbday);
    free(pbsec);
    free(paday);
    free(pasec);

    if(flag){
        printf("VALID DATE: SUCCESS!\n");
        return TRUE;
    }

    printf("VALID DATE: FAILURE!\n");
    return FALSE;
}


/* Check URL in a line of String */
int valid_URL_in_String(char *data, char *url, int not_cn){
    char *tmp_url = url;
    char *head;
    const char dot = '.';
    int num = 0;
    const char dotcom[] = ".com";


    /* If data is not COMMON NAME */
    if(not_cn){
        /* Check URL against data */
        if(!strstr(data, url)){
            return TRUE;
        }

        /* Get to the URL head and add * to match against data as a Wildcard */
        head = strchr(tmp_url, dot);
        printf("INITIAL HEAD: %s\n", head);
        printf("MY WILDCARDS: ");

        while(head != NULL && !strstr(head, dotcom)){
            char wildcard[BUFSIZE] = "*";
            strcat(wildcard, head);
            printf("%s ", wildcard);

            /* Compare newly created wildcard with URL against the input data */
            if(strstr(wildcard, data)){
                printf("\n");
                return TRUE;
            }

            head++;
            head = strchr(head, dot);
            num++;
        }


    /* If data is COMMON NAME */
    }else{

        /* Check URL against data */
        if(!strcmp(data, url)){
            return TRUE;
        }

        /* Get to the URL head and add * to match against data as a Wildcard */
        head = strchr(tmp_url, dot);
        printf("INITIAL HEAD: %s\n", head);
        printf("MY WILDCARDS: ");

        while(head != NULL && strcmp(head, dotcom)){
            char wildcard[BUFSIZE] = "*";
            strcat(wildcard, head);
            printf("%s ", wildcard);

            /* Compare newly created wildcard with URL against the input data */
            if(!strcmp(wildcard, data)){
                printf("\n");
                return TRUE;
            }

            head++;
            head = strchr(head, dot);
            num++;

        }
    }

    printf("\n");

    return FALSE;
}

/* Validate URL against Common Name */
int valid_CN(X509 *cert, char *url){
    int cn_flag = FALSE;
    X509_NAME *subj = X509_get_subject_name(cert);
    char *subj_val;
    char *tmp_val;
    const char dotcom[] = ".com";

    for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
    	X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
    	ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        subj_val = (char *)ASN1_STRING_data(d);

        /* Check if CN matches URL */
        if(strstr(subj_val, dotcom)){
            tmp_val = subj_val;
            if(valid_URL_in_String(subj_val, url, FALSE)){
                cn_flag = TRUE;

            }

            break;
        }
    }

    if(cn_flag){
        printf("VALID CN: SUCCESS! -- CERT URL: %s\n", tmp_val);
        return TRUE;
    }

    printf("VALID CN: FAILURE! -- CERT URL: %s\n", tmp_val);
    return FALSE;
}

/* Validate Basic Constraints */
int valid_BC(char *data){

    if(strstr(data, CONSTRAINTS)){
        printf("VALID CONSTRAINTS: SUCCESS! -- %s\n", data);
        return TRUE;
    }

    printf("VALID CONSTRAINTS: FAILURE! -- %s\n", data);
    return FALSE;
}

/* Validate Enhanced Key Usage */
int valid_EKU(char *data){

    if(strstr(data, USAGE)){
        printf("VALID USAGE: SUCCESS! -- %s\n", data);
        return TRUE;
    }

    printf("VALID USAGE: FAILURE! -- %s\n", data);
    return FALSE;
}

/* Get a particular Extension from the Certificate and validate them */
int find_EXT(X509 *cert, char *url, const char *target_ext_name){
    int san_flag = FALSE;
    int bc_flag = FALSE;
    int eku_flag = FALSE;

    /* Get the Extensions from the Cert */
    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

    /* Count the number of extensions */
    int num_of_exts;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    } else {
        num_of_exts = 0;
    }

    /* If there are no extensions */
    if(num_of_exts < 0){
        printf("ERROR in parsing number of X509v3 extensions!\n");
        return(EXIT_FAILURE);
    }

    /* Iterate for all the extensions */
    for (int i=0; i < num_of_exts; i++) {

    	X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if(!ex){
            printf("ERROR in extracting extensions from stack!\n");
            return(EXIT_FAILURE);
        }

    	ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        if(!obj){
            printf("ERROR in extracting ASN1 object from extensions!\n");
            return(EXIT_FAILURE);
        }

    	BIO *ext_bio = BIO_new(BIO_s_mem());
        if(!ext_bio){
            printf("ERROR in allocating memory for extension value BIO!\n");
            return(EXIT_FAILURE);
        }

    	if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
    		M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
    	}

    	BUF_MEM *bptr;
    	BIO_get_mem_ptr(ext_bio, &bptr);
    	BIO_set_close(ext_bio, BIO_NOCLOSE);

        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
            bptr->data[lastchar-1] = (char) 0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
            bptr->data[lastchar] = (char) 0;
        }
    	BIO_free(ext_bio);

        /* Get NID Object */
    	unsigned nid = OBJ_obj2nid(obj);
    	if (nid != NID_undef) {

            /* Get extension name */
    		const char *ext_name = OBJ_nid2ln(nid);
            if(!ext_name){
                printf("ERROR in X509v3 extension name!\n");
                return(EXIT_FAILURE);
            }

            /* Check Extension Name and Trigger Flag if found */
            if(!strcmp(ext_name, target_ext_name)){
                if(!strcmp(ext_name, SAN)){
                    san_flag = TRUE;
                }else if(!strcmp(ext_name, BC)){
                    bc_flag = TRUE;
                }else if(!strcmp(ext_name, EKU)){
                    eku_flag = TRUE;
                }
            }

    	}

        /* Check for URL valid in SAN field */
        if(san_flag){
            printf("VALID EXT: SUCCESS! -- EXT FOUND: %s\n", target_ext_name);

            if(valid_URL_in_String(bptr->data, url, TRUE)){
                printf("VALID EXT SAN: SUCCESS! -- URL in SAN: %s\n", bptr->data);
                return TRUE;
            }

            printf("VALID EXT SAN: FAILURE! -- URL not in SAN: %s\n", bptr->data);
            return FALSE;

        /* Validate Basic Constraint */
        }else if(bc_flag){
            if(valid_BC(bptr->data)){
                printf("VALID BC: SUCCESS!\n");
                return TRUE;
            }

            printf("VALID BC: FAILURE!\n");
            return FALSE;

        /* Validate Enhanced Key Usage */
        }else if(eku_flag){
            if(valid_EKU(bptr->data)){
                printf("VALID EKU: SUCCESS!\n");
                return TRUE;
            }

            printf("VALID EKU: FAILURE!\n");
            return FALSE;
        }


    }

    printf("VALID EXT: FAILURE! -- EXT NOT FOUND: %s\n", target_ext_name);
    return FALSE;
}

/* Validate URL against Common Name and Subject Alternative Name and Wildcards */
int valid_URL(X509 *cert, char *url){
    int cn_flag = FALSE;
    int ext_san_flag = FALSE;

    if(valid_CN(cert, url)){
        cn_flag = TRUE;
    }

    if(find_EXT(cert, url, SAN)){
        ext_san_flag = TRUE;
    }

    if(cn_flag || ext_san_flag){
        printf("VALID URL: SUCCESS!\n");
        return TRUE;
    }

    printf("VALID URL: FAILURE!\n");
    return FALSE;
}


/* Valid MIN KEY LEN of the Cert */
int valid_MIN_KEY_LEN(X509 *cert, int bit_size){
    int min_key_flag = FALSE;

    /* Get PUB KEY from Cert */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if(!pkey){
        printf("ERROR in extracting public key from certificate!\n");
        exit(EXIT_FAILURE);
    }

    RSA *rsa_key;

    /* Check if Key Algorithm is RSA Encrypted */
    int pubkey_algonid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
    if(pubkey_algonid == NID_rsaEncryption){

        /* Get RSA PUB KEY */
        rsa_key = pkey->pkey.rsa;
        if(!rsa_key){
            printf("ERROR in extracting RSA Public Key!\n");
            exit(EXIT_FAILURE);
        }

        /* Check RSA Pub Key Len */
        int rsa_key_len = BN_num_bits(rsa_key->n);
        if(rsa_key_len >= bit_size){
            min_key_flag = TRUE;
        }

    }

    EVP_PKEY_free(pkey);
    if(min_key_flag == TRUE){
        printf("VALID RSA PUB KEY LEN: SUCCESS! -- %d\n", BN_num_bits(rsa_key->n));
        return TRUE;
    }


    printf("VALID RSA PUB KEY LEN: FAILURE!\n");
    return FALSE;
}


int
main(int argc, char *argv[]){
    /* Get Relative Path from STDIN */
    char* input_path = NULL;
    const char *output_file = "output.csv";
    input_path = argv[1];

    if (!input_path){
        printf("ERROR IN STDIN!\n");
        exit(EXIT_FAILURE);
    }

    /* Find if Output file exist and if it does remove it */
    if(access(output_file, F_OK) != -1){
        if(remove(output_file)){
            printf("Output File EXISTS and has been REMOVED!\n");
        }else{
            printf("Output File EXIST and has NOT been REMOVED!\n");
        }
    }

    /* Variables for BIO and X509 cert and stack */
    BIO *cert_bio = NULL;
    BIO *output_bio = NULL;
    X509 *cert = NULL;
    STACK_OF(X509_EXTENSION) *ext_list;

    /* Initialise openSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Open file */
    FILE *fp = fopen(input_path, "r");
    char input_file[BUFSIZE];
    char input_url[BUFSIZE];
    char file_path[BUFSIZE];
    char path[] = "./";

    int cert_num = 1;
    /* Get URL and Cert */
    while(fscanf(fp, "%[^,],%s ", input_file, input_url) != EOF){

        /* Get Cert File Path */
        strcpy(file_path, path);
        strcat(file_path, input_file);

        /* Create a BIO object to read Cert */
        cert_bio = BIO_new(BIO_s_file());
        output_bio = BIO_new(BIO_s_file());

        /* Read File from File Path into BIO */
        if(!(BIO_read_filename(cert_bio, file_path))){
            printf("ERROR IN READING CERT BIO FILENAME!\n");
            exit(EXIT_FAILURE);
        }

        /* Read BIO into X509 Cert */
        X509* cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
        if(!cert){
            printf("ERROR IN LOADING CERTIFICATE!\n");
            exit(EXIT_FAILURE);
        }

        int valid_num = 0;

        /* ouput FILE CHECK STATUS to Terminal */
        printf("*************************************************************\n");
        printf("*********************CERTIFICATE %d CHECK", cert_num);
        printf("*********************\n");
        printf("*************************************************************\n");
        printf("GIVEN CERT: %s GIVEN URL: %s\n", input_file, input_url);
        printf("-------------------------DATE CHECK--------------------------\n");
        if(valid_DATE(cert)){
            valid_num++;
        }
        printf("-------------------------URL CHECK---------------------------\n");
        if(valid_URL(cert, input_url)){
            valid_num++;
        }
        printf("-------------------------KEY CHECK---------------------------\n");
        if(valid_MIN_KEY_LEN(cert, MIN_KEY_LEN)){
            valid_num++;
        }
        printf("-------------------BASIC CONSTRAINT CHECK--------------------\n");
        if(find_EXT(cert,input_url,BC)){
            valid_num++;
        }
        printf("------------------ENHANCED KEY USAGE CHECK-------------------\n");
        if(find_EXT(cert, input_url, EKU)){
            valid_num++;
        }
        printf("*************************************************************\n");
        printf("*************************");
        printf("(%d/5)=", valid_num);
        if(valid_num == 5){
            printf("SUCCESS");
            record(input_file, input_url, TRUE, output_file);
        }else{
            record(input_file, input_url, FALSE, output_file);
            printf("FAILURE");
        }
        printf("***********************\n");
        printf("*************************************************************\n\n");

        /* Free Mem */
        X509_free(cert);
        BIO_free_all(cert_bio);

        cert_num++;
    }


    /* Close File */
    fclose(fp);

    return 0;

}
