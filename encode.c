#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encode.h"
#include "types.h"
#include "common.h"

// Extern required values from main file
extern uint raster_data, passcode_len, step;
extern uchar magic_string_signature[CHAR_SIZE + MAX_PASSCODE_LEN + CHAR_SIZE];

/* Function Definitions */
/*Validation part-1 started*/
/* 1. Check operation type */
OperationType check_operation_type(char *argv[])
{
	if (!strcmp(*argv, "-e")) // Check if argument is '-e'
		return e_encode;
	else if (!strcmp(*argv, "-d")) // Check if argument is '-d'
		return e_decode;
	else
		return e_unsupported; // Some other argument
}

//---------------------------------------------------
// DESCRIPTION: 
//				If the argument is "-e", it returns e_encode enum value, indicating that the program should perform encoding.
//              If the argument is "-d", it returns e_decode enum value, indicating that the program should perform decoding.
//              If the argument is not recognized, it returns e_unsupported enum value, indicating that the operation type is not supported.
//
// PARAMETERS: 
//				-char *argv[]: A pointer to an array of C-style strings, which represents the command-line arguments passed to the program.
//
// FUNCTION: 
//				This function checks the operation type requested by the user based on the command line arguments passed to the program.
//
//
//---------------------------------------------------

/* 2. Read and validate Encode args from argv */
Status read_and_validate_bmp_format(char *argv[])
{
	// Pointer to hold address of '.bmp' part from given argument
	const char *bmp_holder = strstr(*argv, ".bmp");
	if (bmp_holder) // Error handling
	{				// If '.bmp' part is found, then check if string exactly ends with '.bmp'
		return (!strcmp(bmp_holder, ".bmp")) ? e_success : e_failure;
	}
	return e_failure; // NULL address which means '.bmp' part is not found
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION: 
//				Read and validate Encode args from argv
//
//
//---------------------------------------------------


/* ------------------------3------------------------ */
Status read_and_validate_extn(uchar_ptr sec_file_name_holder, EncodeInfo *encInfo)
{
	// Pointer to hold the heap memory of the size of filename including '\0' character
	uchar_ptr sec = (uchar_ptr)malloc(strlen((const char *)sec_file_name_holder) + 1);
	if (sec == NULL)
	{
		printf("ERROR: Unable to allocate dynamic memory.\n\n");
		return e_failure;
	}
	strcpy((char *)sec, (const char *)sec_file_name_holder); // Store the filename inside allocated heap
	uint secret_filename_len = strlen((const char *)sec);	 // Get length of filename
	char *ext = strtok((char *)sec, ".");					 // Get part of string before dot
	// If there is no dot in the filename, length of string remains the same
	if (strlen(ext) == secret_filename_len)
	{
		printf("ERROR: There is no dot in the given filename.\n");
		return e_failure;
	}
	// Extract the extension of secret file (i.e. part of string after dot)
	ext = strtok(NULL, ".");
	strcpy((char *)encInfo->extn_secret_file, (const char *)ext); // Store the extracted extension
	// Get and store length of secret extension
	encInfo->secret_extn_len = strlen((const char *)encInfo->extn_secret_file);
	// Validate extension size
	if (encInfo->secret_extn_len > MAX_FILE_SUFFIX)
	{
		printf("ERROR: file extension should not exceed 4 characters\n");
		return e_failure;
	}
	free(sec);		  // Free the allocated block of memory
	return e_success; // No errors found
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//				Read, validate and extract secret file extension
//
//---------------------------------------------------
 

/* ------------------------4------------------------ */
Status no_digits(const char *str)
{
	while (*str != '\0') // Iterate till end of string
	{
		if (*str < '0' || *str > '9') // If any non-digit character found
			return e_success;
		str++;
	}
	return e_failure; // All characters are digits
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//				Function to check non-digit character in passcode
//
//---------------------------------------------------

/* ------------------------5. Get File pointers for i/p and o/p files */
Status open_files(EncodeInfo *encInfo)
{
	// Open source image file with proper error handling
	if ((encInfo->fptr_src_image = fopen((const char *)encInfo->src_image_fname, "rb")) == NULL)
	{
		perror("fopen");
		fprintf(stderr, "ERROR: Unable to open file %s. This file may not be present in the current project directory.\n\n", encInfo->src_image_fname);
		return e_failure;
	}
	// Open secret file with proper error handling
	if ((encInfo->fptr_secret = fopen((const char *)encInfo->secret_fname, "rb")) == NULL)
	{
		perror("fopen");
		fprintf(stderr, "ERROR: Unable to open file %s. This file may not be present in the current project directory.\n\n", encInfo->secret_fname);
		return e_failure;
	}
	// Open output image file with proper error handling
	if ((encInfo->fptr_stego_image = fopen((const char *)encInfo->stego_image_fname, "wb")) == NULL)
	{
		perror("fopen");
		fprintf(stderr, "ERROR: Unable to open file %s. This file may not be present in the current project directory.\n\n", encInfo->stego_image_fname);
		return e_failure;
	}
	return e_success; // No error found
}
/*Validation part-1 completed*/

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//
//
//---------------------------------------------------


/*Validation part-2 started*/
/* ------------------------6. Copy bmp image header */
Status copy_bmp_header(FILE *fptr_src_image, FILE *fptr_dest_image)
{
	// Store image header of the size of raster data into a block of heap memory
	uchar_ptr img_header = (uchar_ptr)malloc(raster_data * sizeof(uchar));
	if (img_header == NULL) // Error handling for malloc
	{
		printf("ERROR: Unable to allocate dynamic memory.\n\n");
		exit(e_success);
	}
	// Read bytes of the size of raster data from source file
	fread(img_header, raster_data, 1, fptr_src_image);
	if (ferror(fptr_src_image)) // Error handling while reading from file
	{
		printf("ERROR: Error in reading source image file.\n\n");
		return e_failure;
	}
	// Write data obtained in heap onto the destination file
	fwrite(img_header, raster_data, 1, fptr_dest_image);
	if (ferror(fptr_dest_image)) // Error handling while writing onto destination file
	{
		printf("ERROR: Error in writing onto destination image file.\n\n");
		return e_failure;
	}
	free(img_header); // Free dynamically allocated block of memory
	return e_success; // No error found
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//
//
//---------------------------------------------------

/* ------------------------7. Get image size */
uint get_image_size_for_bmp(FILE *fptr_image)
{
	uint img_size; // Return value to be read from image file
	// Seek to 34th byte to get image data size from the '.bmp' image file
	fseek(fptr_image, 34L, SEEK_SET);
	// Read the width (an unsigned integer)
	fread(&img_size, sizeof(img_size), 1, fptr_image);
	if (ferror(fptr_image))
	{
		printf("ERROR: Error while reading from the image file.\n\n");
		exit(e_success);
	}
	// Return image capacity
	return img_size;
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//
//
//---------------------------------------------------

/* ------------------------8. Get file size */
uint get_file_size(FILE *fptr) // Returns file size including EOF byte
{
	// Seek to the end of file
	fseek(fptr, 0L, SEEK_END);
	return (uint)ftell(fptr); // Return file index value
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//
//
//---------------------------------------------------

/* ------------------------9. Check capacity */
Status check_capacity(EncodeInfo *encInfo)
{
	// Print messages
	printf("INFO.%d: Image data size = %u bytes\n", ++step, encInfo->image_capacity);
	printf("INFO.%d: Magic string size = %u bytes\n", ++step, encInfo->magic_string_size);
	// Check if image data size is greater than magic string size
	return (encInfo->magic_string_size < encInfo->image_capacity) ? e_success : e_failure;
}
/*Validation part-2 completed*/

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//
//
//---------------------------------------------------


/*Encoding part started*/
/* ------------------------10. Perform encoding */
Status do_encoding(EncodeInfo *encInfo)
{
	// Encode magic string signature
	printf("INFO.%d: Encoding Magic String Signature\n", ++step);
	fseek(encInfo->fptr_src_image, raster_data, SEEK_SET);
	if (encode_magic_string((const char *)magic_string_signature, encInfo))
	{
		printf("INFO.%d: Magic string signature successfully encoded.\n", ++step);
	}
	else
	{
		printf("ERROR: Error while encoding magic string signature.\n\n");
		return e_failure;
	}
	// Check if passcode is given
	if (passcode_len)
	{
		// Encode passcode length
		printf("INFO.%d: Encoding passcode length\n", ++step);
		if (encode_int_size_expression(passcode_len, encInfo))
		{
			printf("INFO.%d: Passcode length successfully encoded.\n", ++step);
		}
		else
		{
			printf("ERROR: Error while encoding passcode length.\n\n");
			return e_failure;
		}
		// Encode passcode
		printf("INFO.%d: Encoding the passcode\n", ++step);
		if (encode_magic_string((const char *)encInfo->passcode, encInfo))
		{
			printf("INFO.%d: Successfully encoded the passcode.\n", ++step);
		}
		else
		{
			printf("ERROR: Error while encoding the passcode.\n\n");
			return e_failure;
		}
	}
	// Encode secret file extension length
	printf("INFO.%d: Encoding secret file extension length\n", ++step);
	if (encode_int_size_expression(encInfo->secret_extn_len, encInfo))
	{
		printf("INFO.%d: Secret file extension length successfully encoded.\n", ++step);
	}
	else
	{
		printf("ERROR: Error while encoding secret file extension length.\n\n");
		return e_failure;
	}
	// Encode the dot in secret file name
	printf("INFO.%d: Encoding the dot in secret file name\n", ++step);
	if (encode_magic_string(".", encInfo))
	{
		printf("INFO.%d: Successfully encoded the dot.\n", ++step);
	}
	else
	{
		printf("ERROR: Error while encoding the dot.\n\n");
		return e_failure;
	}
	// Encode the secret file extension
	printf("INFO.%d: Encoding the secret file extension\n", ++step);
	if (encode_magic_string((const char *)(encInfo->extn_secret_file), encInfo))
	{
		printf("INFO.%d: Successfully encoded the secret file extension.\n", ++step);
	}
	else
	{
		printf("ERROR: Error while encoding the secret file extension.\n\n");
		return e_failure;
	}
	// Encode the secret file size
	printf("INFO.%d: Encoding the secret file size\n", ++step);
	if (encode_int_size_expression(encInfo->size_secret_file - CHAR_SIZE, encInfo))
	{
		printf("INFO.%d: Secret file size successfully encoded.\n", ++step);
	}
	else
	{
		printf("ERROR: Error while encoding secret file size.\n\n");
		return e_failure;
	}
	// Encode the secret data
	// Let's create a string to store the secret_data
	uchar_ptr secret_data = (uchar_ptr)malloc(encInfo->size_secret_file * sizeof(uchar));
	if (secret_data == NULL)
	{
		printf("ERROR: Unable to allocate dynamic memory.\n\n");
		return e_failure;
	}
	rewind(encInfo->fptr_secret);
	fread(secret_data, encInfo->size_secret_file * sizeof(uchar) - CHAR_SIZE, 1, encInfo->fptr_secret);
	secret_data[encInfo->size_secret_file - CHAR_SIZE] = '\0'; // Set last character as NUL character
	// Now let's encode secret data
	printf("INFO.%d: Encoding the secret data\n", ++step);
	if (encode_magic_string((const char *)secret_data, encInfo))
	{
		printf("INFO.%d: Successfully encoded the secret data.\n", ++step);
	}
	else
	{
		printf("ERROR: Error while encoding the secret data.\n\n");
		return e_failure;
	}
	free(secret_data);
	// Copy remaining image bytes
	printf("INFO.%d: Copying the left over data\n", ++step);
	if (copy_remaining_image_data((FILE *)encInfo->fptr_src_image, (FILE *)encInfo->fptr_stego_image, encInfo->image_capacity - encInfo->magic_string_size + CHAR_SIZE)) // To append EOF i.e. the last byte, we should add byte size
	{
		printf("INFO.%d: Remaining image data copied to output file successfully.\n", ++step);
	}
	else
	{
		printf("ERROR: Failed to copy remaining image data\n\n");
		return e_failure;
	}
	return e_success; // No error found
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//				Perform encoding
//
//---------------------------------------------------

/* ------------------------11. Encode Magic String */
Status encode_magic_string(const char *magic_string, EncodeInfo *encInfo)
{
	uchar scan_char; // Read and store each byte into a character
	// Outer iteration till the size of given string
	for (uint i = 0; i < strlen(magic_string); i++)
	{
		for (int j = 7; j >= 0; j--) // 8 times inner iteration, Note that iterator j should not be of the type uint.
		{							 // Read each byte
			fread(&scan_char, sizeof(scan_char), 1, encInfo->fptr_src_image);
			if (ferror(encInfo->fptr_src_image)) // Error handling
			{
				printf("ERROR: Error while reading from source image file.\n\n");
				return e_failure;
			}
			scan_char &= 0xFE;				 // Clear the least significant bit of fetched character
			if (magic_string[i] & (01 << j)) // Check every bit of magic string
			{
				scan_char |= 01; // Set the least significant bit of obtained character
			}
			else
			{
				scan_char |= 00; // Clear the least significant bit of obtained character
			}
			// Write the obtained byte into output file
			fwrite(&scan_char, sizeof(scan_char), 1, encInfo->fptr_stego_image);
			if (ferror(encInfo->fptr_stego_image)) // Error handling
			{
				printf("ERROR: Error while writing onto output image file.\n\n");
				return e_failure;
			}
		}
	}
	return e_success; // No errors found
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//				Encode Magic String
//
//---------------------------------------------------

/* ------------------------12. Encode secret file extenstion */
Status encode_int_size_expression(uint len, EncodeInfo *encInfo)
{
	uchar scan_char;							// Read and store each byte into a character
	for (int j = INT_SIZE * 8 - 1; j >= 0; j--) // Fetch every byte till integer size
	{
		// Read each byte
		fread(&scan_char, sizeof(scan_char), 1, encInfo->fptr_src_image);
		if (ferror(encInfo->fptr_src_image)) // Error handling
		{
			printf("ERROR: Error while reading from source image file.\n\n");
			return e_failure;
		}
		scan_char &= 0xFE;	// Clear the least significant bit of obtained character
		if (len & (1 << j)) // Check every bit of obtained length
		{
			scan_char |= 01; // Set the least significant bit of obtained character
		}
		else
		{
			scan_char |= 00; // Clear the least significant bit of obtained character
		}
		// Write obtained byte onto output file
		fwrite(&scan_char, sizeof(scan_char), 1, encInfo->fptr_stego_image);
		if (ferror(encInfo->fptr_stego_image)) // Error handling
		{
			printf("ERROR: Error while writing into output image file.\n\n");
			return e_failure;
		}
	}
	return e_success; // No errors found
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//				Encode secret file extenstion
//
//---------------------------------------------------

/* ------------------------13. Copy remaining image bytes from src_image to dest_image after encoding */
Status copy_remaining_image_data(FILE *fptr_src_image, FILE *fptr_dest_image, uint f_size)
{
	// Pointer to hold heap memory of the size of file
	uchar_ptr ch = (uchar_ptr)malloc(f_size * sizeof(uchar));
	if (ch == NULL)
	{
		printf("ERROR: Unable to allocate dynamic memory.\n\n");
		return e_failure;
	}
	fread(ch, f_size, 1, fptr_src_image); // Read and store all the data of file size
	if (ferror(fptr_src_image))			  // Error handling
	{
		printf("ERROR: Error in reading from source file.\n\n");
		return e_failure;
	}
	fwrite(ch, f_size, 1, fptr_dest_image); // Write the obtained data onto output file
	if (ferror(fptr_dest_image))			// Error handling
	{
		printf("ERROR: Error in writing onto output file.\n\n");
		return e_failure;
	}
	free(ch); // Free allocated heap memory
	return e_success;
}

//---------------------------------------------------
// DESCRIPTION:
//
// PARAMETERS:
//
// FUNCTION:
//				Copy remaining image bytes from src_image to dest_image after encoding
//
//---------------------------------------------------


/*End of encoding part*/
