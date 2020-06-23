/* Userspace frontend used 
 * to use '/dev/cryptodev' 
 * character device.
 * This tool can send/retrieve
 * encrypted/decrypted data
 * from the kernel 
 * (c) 2020 - Marco Cetica */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#define BUFFER_LEN 256

int main(void) {
	int ret, dev;
	char data_to_send[BUFFER_LEN]; // Data to be sent to the kernel
	char buffer[BUFFER_LEN]; // Data from the Kernel

	// Open the device
	puts("Opening character device...");
	dev = open("/dev/cryptodev", O_RDWR); // Open the device using syscall in read/write mode
	if(dev < 0) { // handle errors
		perror("Failed to open the device");
		return errno;
	}

	// Reading from stdin
	fputs("Insert a string: ", stdout);
	if(fgets(data_to_send, sizeof(data_to_send), stdin) == NULL) {
		puts("Error while reading from stdin");
		return -1;
	}

	// Removeing \n char from string
	strtok(data_to_send, "\n");

	// Sending data to the device
	puts("Hashing string, please wait...");
	ret = write(dev, data_to_send, strlen(data_to_send)); // Write the string using Linux syscall
	if(ret < 0) { // handle errors
		perror("Failed to write data to the device");
		return errno;
	}

	// Reading from the device
	ret = read(dev, buffer, BUFFER_LEN); // Read from the device using Linux syscall
	if(ret < 0) { // Handle errors
		perror("Failed to read from the device");
		return errno;
	}

	// Print buffer in hex 
	printf("Original: '%s', MD5 digest: '", data_to_send);
	for(size_t i = 0; i < 16; i++)
		printf("%02x", (unsigned char)buffer[i]);
	puts("'");
	return 0;
}
