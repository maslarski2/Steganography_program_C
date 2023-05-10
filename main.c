 
//Name:Viktor Maslarski
//Date: 03/05/2023
//Project Description: LSB Image Steganography
//Sample Input:-> 
//					./a.out -e iamge.bmp secret.txt 
//Sample Output:->
//					INFO: Opening required files
//					INFO: Opened iamge.bmp
//					INFO: Opened secret.txt
//					INFO: Opened steged_img.bmp
//					INFO: Done
//					INFO: ## Encoding Procedure Started ##
//					INFO: Checking for secret.txt size
//					INFO: Done. Not Empty
//					INFO: Checking for img.bmp capacity to handle secret.txt
//					INFO: Done. Found OK
//					INFO: Output File not mentioned. Creating steged_img.bmp as default
//					INFO: Copying Image Header
//					INFO: Done
//					INFO: Encoding Magic String Signature
//					INFO: Done
//					INFO: Encoding secret.txt File Extenstion
//					INFO: Done
//					INFO: Encoding secret.txt File Size
//					INFO: Done
//					INFO: Encoding secret.txt File Data
//					INFO: Done
//					INFO: Copying Left Over Data
//					INFO: Done
//					INFO: ## Encoding Done Successfully ##


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encode.h"
#include "types.h"
#include <libgen.h>

/* Global variables. These will be externed into other files */
// Store raster data index, file index, length of secret filename
// Flags indicating need of passcode and need of default file extension
uint raster_data, secret_filename_len, default_ext_name = 0, passcode_flag = 0, passcode_len = 0, step = 0, d_step = 1;
// string for storing magic string signature: * or # with '\0' character
uchar magic_string_signature[CHAR_SIZE + CHAR_SIZE];
// string storing temporary user provided decode filename
uchar temp_decode_name[MAX_FILENAME_SIZE];

int main(int argc, char *argv[])
{
	/*Validation part-1 started*/
	EncodeInfo encInfo; // Structure variable
	printf("\nINFO.%d: Verifying inputs...\n", ++step);
	if (argc < 3)
	{
		printf("ERROR: Invalid number of command line arguments.\n\n");
		return 1;
	}
	if (check_operation_type(argv + 1) == e_encode)
	{
		printf("INFO.%d: Encoding operation requested.\n", ++step);
		if (argc < 4 || argc > 7)
		{
			printf("ERROR: Invalid number of command line arguments.\n\n");
			return 1;
		}
		// Read and validate src_image filename
		// Extract only filename from given path if any
		argv[2] = basename(argv[2]);
		printf("INFO.%d: Verifying source image filename...\n", ++step);
		if (read_and_validate_bmp_format(argv + 2) == e_failure)
		{
			printf("ERROR: Invalid filename provided in 2nd command line argument. It must be a '.bmp' file.\n\n");
			return 1;
		}
		printf("INFO.%d: Valid source image filename.\n", ++step);
		strcpy((char *)encInfo.src_image_fname, argv[2]);
		// Validate and assign 3rd command line argument as secret filename
		printf("INFO.%d: Verifying secret filename...\n", ++step);
		// Extract only filename from given path if any
		argv[3] = basename(argv[3]);
		if (read_and_validate_extn((uchar_ptr)argv[3], &encInfo))
		{
			printf("INFO.%d: Valid secret filename.\n", ++step);
		}
		else
		{
			printf("ERROR: Invalid secret filename.\n\n");
			return 1;
		}
		strcpy((char *)encInfo.secret_fname, argv[3]);
		switch (argc)
		{
		case 4:
			// Giving default output filename since no 4th command line argument is given
			strcpy((char *)encInfo.stego_image_fname, "stego_img.bmp");
			printf("INFO.%d: No output filename given. Creating default output image file %s in current project directory.\n", ++step, encInfo.stego_image_fname);
			break;
		case 5:
			// Read and validate given output filename
			// Extract only filename from given path if any
			argv[4] = basename(argv[4]);
			printf("INFO.%d: Verifying output image filename...\n", ++step);
			if (read_and_validate_bmp_format(argv + 4) == e_failure)
			{
				printf("ERROR: Invalid filename provided in 4th command line argument. It must be user provided '.bmp' file.\n\n");
				return 1;
			}
			printf("INFO.%d: Valid output image filename.\n", ++step);
			strcpy((char *)encInfo.stego_image_fname, argv[4]);
			printf("INFO.%d: Assigning Output filename as %s\n", ++step, encInfo.stego_image_fname);
			break;
		case 6:
			if (strcmp(argv[4], "-p"))
			{
				printf("ERROR: Invalid 4th argument. Please use '-p' and a passcode in the next argument.\n\n");
				return 1;
			}
			printf("INFO.%d: Verifying passcode...\n", ++step);
			if (strlen(argv[5]) > MAX_PASSCODE_LEN || no_digits(argv[5]))
			{
				printf("ERROR: Passcode must include maximum %d 'digits'.\n\n", MAX_PASSCODE_LEN);
				return 1;
			}
			printf("INFO.%d: Passcode accepted!!\n", ++step);
			strcpy((char *)encInfo.passcode, argv[5]);
			passcode_flag = 1;
			passcode_len = strlen((const char *)encInfo.passcode);
			// Giving default output filename since no fifth argument is passed
			strcpy((char *)encInfo.stego_image_fname, "stego_img.bmp");
			printf("INFO.%d: No output filename given. Creating default output image file %s in current project directory\n", ++step, encInfo.stego_image_fname);
			break;
		default: // case 7
			// Read and validate given output filename
			// Extract only filename from given path if any
			argv[4] = basename(argv[4]);
			if (read_and_validate_bmp_format(argv + 4) == e_failure)
			{
				printf("ERROR: Invalid filename provided in 4th command line argument. It must be user provided output '.bmp' file.\n\n");
				return 1;
			}
			strcpy((char *)encInfo.stego_image_fname, argv[4]);
			printf("INFO.%d: Output filename is provided as %s\n", ++step, encInfo.stego_image_fname);
			if (strcmp(argv[5], "-p"))
			{
				printf("ERROR: Invalid 5th argument. Please use '-p' and a passcode in the next argument.\n\n");
				return 1;
			}
			printf("INFO.%d: Verifying passcode...\n", ++step);
			if (strlen(argv[6]) > MAX_PASSCODE_LEN || no_digits(argv[6]))
			{
				printf("ERROR: Passcode must include maximum %d 'digits'.\n\n", MAX_PASSCODE_LEN);
				return 1;
			}
			printf("INFO.%d: Passcode accepted!!\n", ++step);
			strcpy((char *)encInfo.passcode, argv[6]);
			passcode_flag = 1;
			passcode_len = strlen((const char *)encInfo.passcode);
		}
		// Test open_files
		printf("INFO.%d: Opening all the necessary files...\n", ++step);
		if (open_files(&encInfo) == e_success)
		{
			printf("INFO.%d: All files successfully opened.\n\n", ++step);
		}
		else
			return 1;
		/*Validation part-1 completed*/

		//---------------------------------------------------
		// DESCRIPTION:
		// 				 If the function open_files returns e_failure, the program returns an error code of 1 and terminates using the return statement.
		// 				 The open_files function is responsible for opening the necessary files (source image file, secret file, and steganographed image file) for performing encoding or decoding operation.
		// 				 If any of the file openings fail, the function returns e_failure, and the program terminates with an error message.
		//
		// PARAMETERS:
		//
		// FUNCTION: 
		//				 Validation
		//
		//---------------------------------------------------


		/*Validation part-2 started*/
		printf("INFO.%d: Obtaining offset to image raster data...\n", ++step);
		// Collect raster data offset: seek to 10th index of bmp file
		fseek(encInfo.fptr_src_image, 10L, SEEK_SET);
		fread(&raster_data, sizeof(raster_data), 1, encInfo.fptr_src_image);
		if (ferror(encInfo.fptr_src_image))
		{ // Error handling
			printf("ERROR: Error while reading from file %s\n\n", encInfo.src_image_fname);
			return 1;
		}
		printf("INFO.%d: Offset to image raster data found at %u.\n", ++step, raster_data);
		rewind(encInfo.fptr_src_image);
		printf("INFO.%d: Copying image header to output file...\n", ++step);
		// Copy image header
		if (copy_bmp_header((FILE *)encInfo.fptr_src_image, (FILE *)encInfo.fptr_stego_image))
		{
			printf("INFO.%d: Image header copied to output file successfully.\n", ++step);
		}
		else
		{
			printf("ERROR: Failed to copy image header.\n\n");
			return 1;
		}
		// Image data size should be larger than Magic String Size
		printf("INFO.%d: Verifying source image size...\n", ++step);
		encInfo.image_capacity = get_image_size_for_bmp(encInfo.fptr_src_image);
		if (!encInfo.image_capacity)
		{
			printf("ERROR: Source image file is empty.\n\n");
			return 1;
		}
		printf("INFO.%d: Source image file is not empty.\n", ++step);
		printf("INFO.%d: Verifying secret file size...\n", ++step);
		encInfo.size_secret_file = get_file_size(encInfo.fptr_secret);
		if (!encInfo.size_secret_file)
		{
			printf("ERROR: Secret file to be encoded is empty.\n\n");
			return 1;
		}
		printf("INFO.%d: Secret file is not empty.\n", ++step);
		printf("INFO.%d: Secret data size = %lu bytes.\n", ++step, encInfo.size_secret_file - CHAR_SIZE); // Last byte i.e. EOF is not considered in actual secret data size
		if (passcode_flag)
		{
			// Magic string size would be having additional passcode length + passcode
			// Magic string = MSS + passcode length + passcode + secret file extn size + dot + file extn + secret data size + secret data
			encInfo.magic_string_size = (CHAR_SIZE + INT_SIZE + passcode_len + INT_SIZE + CHAR_SIZE + encInfo.secret_extn_len + INT_SIZE + encInfo.size_secret_file - CHAR_SIZE) * 8;
			strcpy((char *)magic_string_signature, MAGIC_STRING_WITH_PASSCODE);
		}
		else
		{ // Magic string size without passcode
			// Magic string = MSS + secret file extn size + dot + file extn + secret data size + secret data
			encInfo.magic_string_size = (CHAR_SIZE + INT_SIZE + CHAR_SIZE + encInfo.secret_extn_len + INT_SIZE + encInfo.size_secret_file - CHAR_SIZE) * 8;
			strcpy((char *)magic_string_signature, MAGIC_STRING);
		}
		// Check encoding capacity
		printf("INFO.%d: Verifying encoding capacity...\n", ++step);
		check_capacity(&encInfo) ? printf("INFO.%d: Image data size is sufficient to encode the secret data.\n\n", ++step) : printf("ERROR: Image data size is insufficient to encode the secret data\n\n");
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
		printf("INFO.%d: ##--------Encoding Procedure Started---------##\n", ++step);
		if (do_encoding(&encInfo))
		{
			printf("INFO.%d: ##------Encoding Operation Successful!!------##\n\n", ++step);
		}
		else
		{
			printf("ERROR: ##------Encoding Operation Failed!!------##\n\n");
			return 1;
		}
		fclose(encInfo.fptr_src_image); // close source image file
		fclose(encInfo.fptr_secret);	// Close secret file
	}
	/*Encoding part completed*/

	//---------------------------------------------------
	// DESCRIPTION:
	//
	// PARAMETERS:
	//
	// FUNCTION:
	//
	//
	//---------------------------------------------------


	/*Decoding part started*/
	else if (check_operation_type(argv + 1) == e_decode) // Decoding
	{
		printf("INFO.%d: Decoding operation requested.\n", ++d_step);
		if (argc > 6)
		{
			printf("Error: Invalid number of command line arguments.\n\n");
			return 1;
		}
		// Read and validate given output filename
		printf("INFO.%d: Verifying image filename...\n", ++d_step);
		// Extract only filename from given path if any
		argv[2] = basename(argv[2]);
		if (read_and_validate_bmp_format(argv + 2) == e_failure)
		{
			printf("ERROR: Invalid filename provided in 4th command line argument. It must be a '.bmp' file.\n\n");
			return 1;
		}
		printf("INFO.%d: Valid image filename.\n", ++d_step);
		strcpy((char *)encInfo.stego_image_fname, argv[2]);
		switch (argc)
		{
		// For argc = 3, wait for file extension decoding
		case 3:
			default_ext_name = 1;
			break;
		case 4: // User defined decoded filename
			// Extract only filename from given path if any
			argv[3] = basename(argv[3]);
			strcpy((char *)temp_decode_name, argv[3]);
			printf("INFO.%d: Decode filename is provided as %s\n", ++d_step, temp_decode_name);
			break;
		case 5: // default decoded filename, -p and pass code
			default_ext_name = 1;
			if (strcmp(argv[3], "-p"))
			{
				printf("ERROR: Invalid 3rd argument. Please use '-p' & a passcode as next argument.\n\n");
				return 1;
			}
			if (strlen(argv[4]) > MAX_PASSCODE_LEN || no_digits(argv[4]))
			{
				printf("ERROR: Invalid pass code. Passcode must include maximum %d 'digits'\n\n", MAX_PASSCODE_LEN);
				return 1;
			}
			strcpy((char *)encInfo.passcode, argv[4]);
			passcode_flag = 1;
			passcode_len = strlen((const char *)encInfo.passcode);
			break;
		default: // argc = 6, User defined decoded filename, -p and pass code
			// Extract only filename from given path if any
			argv[3] = basename(argv[3]);
			strcpy((char *)temp_decode_name, argv[3]);
			printf("INFO.%d: Decode filename is provided as %s\n", ++d_step, temp_decode_name);
			if (strcmp(argv[4], "-p"))
			{
				printf("ERROR: Invalid 4th argument. Please use '-p' for pass code & 4-character pass code as next argument.\n\n");
				return 1;
			}
			if (strlen(argv[5]) > MAX_PASSCODE_LEN || no_digits(argv[5]))
			{
				printf("ERROR: Invalid pass code. Passcode must include maximum %d 'digits'\n\n", MAX_PASSCODE_LEN);
				return 1;
			}
			strcpy((char *)encInfo.passcode, argv[5]);
			passcode_flag = 1;
			passcode_len = strlen((const char *)encInfo.passcode);
		}
		// Open stegged image file
		printf("INFO.%d: Opening the image file\n", ++d_step);
		if ((encInfo.fptr_stego_image = fopen((const char *)encInfo.stego_image_fname, "rb")) == NULL)
		{
			printf("ERROR: Unable to open file %s. This file may not be present in the current project directory.\n\n", encInfo.stego_image_fname);
			return 1;
		}
		printf("INFO.%d: Image file successfully opened.\n\n", ++d_step);
		// Collect raster data offset
		printf("INFO.%d: Obtaining offset to image raster data\n", ++d_step);
		fseek(encInfo.fptr_stego_image, 10L, SEEK_SET);
		fread(&raster_data, sizeof(raster_data), 1, encInfo.fptr_stego_image);
		printf("INFO.%d: Offset to image raster data found at %u.\n\n", ++d_step, raster_data);
		fseek(encInfo.fptr_stego_image, raster_data, SEEK_SET);
		if (ferror(encInfo.fptr_stego_image))
		{
			printf("ERROR: Error while reading file %s\n\n", encInfo.stego_image_fname);
			return 1;
		}
		// Stego file index is now pointing at the end of raster data
		// Decode Magic String Signature
		printf("INFO.%d: ##--------Decoding procedure started--------##\n", ++d_step);
		if (do_decoding(&encInfo))
		{
			printf("INFO.%d: ##------Decoding operation successful!!------##\n\n", ++d_step);
		}
		else
		{
			printf("ERROR: ##------Decoding operation failed!!------##\n\n");
			return 1;
		}
		// close decoded output file
		fclose(encInfo.fptr_decoded_file);
	}
	/*Decoding part completed*/
	//---------------------------------------------------
	// DESCRIPTION:
	//
	// PARAMETERS:
	//
	// FUNCTION:
	//
	//
	//---------------------------------------------------

	else
	{ // e_unsupported - Neither encoding nor decoding option
		printf("ERROR: 1st command line argument must be either '-e' for encoding or '-d' for decoding\n\n");
		return 1;
	}
	// Close the output file
	fclose(encInfo.fptr_stego_image); // common file both in encoding & decoding part
	return 0;
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
