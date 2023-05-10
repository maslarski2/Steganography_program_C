#ifndef ENCODE_H
#define ENCODE_H

#include "types.h" // Contains user defined types
#include "common.h"

//-----------------------------------------------------------------
//  Structure to store information required for
//  encoding & decoding secret file to/from image file
//  Info about output and intermediate data is also stored
//-----------------------------------------------------------------

#define MAX_FILENAME_SIZE   50
#define MAX_FILE_SUFFIX     4
#define MAX_PASSCODE_LEN    4
#define INT_SIZE            sizeof(int)
#define CHAR_SIZE           sizeof(char)

typedef struct _EncodeInfo
{
    uchar passcode[MAX_PASSCODE_LEN];
    /* Source Image info */
    FILE *fptr_src_image;
    uchar src_image_fname[MAX_FILENAME_SIZE];
    uint image_capacity;
    /* Secret File Info */
    FILE *fptr_secret;
    uchar secret_fname[MAX_FILENAME_SIZE];
    uchar extn_secret_file[MAX_FILE_SUFFIX + CHAR_SIZE];
    uint size_secret_file;
    uint magic_string_size;
    uint secret_extn_len;
    /* Stego Image Info */
    FILE *fptr_stego_image;
    uchar stego_image_fname[MAX_FILENAME_SIZE];
    /*Decoded File Info */
    FILE* fptr_decoded_file;
    uchar decoded_fname[MAX_FILENAME_SIZE];
} EncodeInfo;

/* Function prototypes */

/* 1. Check operation type */
OperationType check_operation_type(char *argv[]);

/* 2. Read and validate Encode args from argv */
Status read_and_validate_bmp_format(char *argv[]);

/* 3. Read, validate and extract secret file extension */
Status read_and_validate_extn(uchar_ptr sec_file_name_holder, EncodeInfo *encInfo);

/* 4. Function to check non-digit character in passcode*/
Status no_digits(const char* str);

/* 5. Get File pointers for i/p and o/p files */
Status open_files(EncodeInfo *encInfo);

/* 6. Copy bmp image header */
Status copy_bmp_header(FILE *fptr_src_image, FILE *fptr_dest_image);

/* 7. Get image size */
uint get_image_size_for_bmp(FILE *fptr_image);

/* 8. Get file size */
uint get_file_size(FILE *fptr);

/* 9. Check capacity */
Status check_capacity(EncodeInfo *encInfo);

/* 10. Perform encoding */
Status do_encoding(EncodeInfo *encInfo);

/* 11. Encode Magic String */
Status encode_magic_string(const char *magic_string, EncodeInfo *encInfo);

/* 12. Encode secret file extenstion */
Status encode_int_size_expression(uint len, EncodeInfo *encInfo);

/* 13. Copy remaining image bytes from src_image to dest_image after encoding */
Status copy_remaining_image_data(FILE *fptr_src, FILE *fptr_dest, uint f_size);

/* 14. Perform decoding */
Status do_decoding(EncodeInfo *encInfo);

/* 15. Decode magic string */
uchar_ptr decode_magic_string(uint size, EncodeInfo *encInfo);

/* 16. Decode int size expression */
uint decode_int_size_expression(EncodeInfo *encInfo);

/* 17. Decode secret file data */
Status decode_file_data(uint f_size, EncodeInfo *encInfo);

#endif