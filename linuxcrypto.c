/* Loadable Kernel Module(LKM) that 
 * create a character device able
 * to hash a message from userspace
 * using MD5 algorithm. This driver uses 
 * standard Linux kernel cryptographic APIs,
 * however it's just a minimal example of 
 * driver development, so do not use it 
 * on production environments. 
 * (c) Marco Cetica 2020 */
#include <linux/init.h> // Default macros for __init and __exit functions
#include <linux/module.h> // Needed by every module
#include <linux/device.h> // Needed to support Kernel Driver Model
#include <linux/kernel.h> // Other macros
#include <linux/fs.h> // Header for Linux file system support
#include <linux/uaccess.h> // Needed for 'copy_to_user' method
#include <crypto/hash.h> // Needed for MD5 hashing
#include <linux/slab.h>  // Needed for kmalloc and kfree
#define DEVICE_NAME "cryptodev" // Name of the device
#define DEVICE_CLASS "crypto" // Name of the class

// Module infos
MODULE_AUTHOR("Marco Cetica");
MODULE_DESCRIPTION("Char device that computer MD5.");
MODULE_VERSION("0.1");
MODULE_LICENSE("Dual BSD/GPL");

// Definition of global variables(only available into this file)
static int device_number; // Number of character device, aka major number
static char userspace_msg[256] = {0}; // Data from userspace with fixed size
static short size_of_msg; // Actual buffer size
static char hashed_data[16] = {0}; // Result of hashing function
static int open_count = 0; // Number of times device has been opened
static struct class* cryptodev_class = NULL; // device driver class pointer
static struct device* cryptodev_device = NULL; // device driver device pointer

// Function prototypes(NOTE: needed before struct)
static int cryptodev_open(struct inode*, struct file*);
static int cryptodev_close(struct inode*, struct file*);
static ssize_t cryptodev_read(struct file*, char*, size_t, loff_t*);
static ssize_t cryptodev_write(struct file*, const char*, size_t, loff_t*);


/* File operation struct
 * Here we can map callback functions to default syscalls. */
static struct file_operations fo = {
	.open = cryptodev_open,
	.release = cryptodev_close,
	.read = cryptodev_read,
	.write = cryptodev_write,
};

// Entry point functions: __init and __exit
static int __init cryptodev_init(void) {
	printk(KERN_INFO "cryptodev: Loading, please wait...\n");

	// Obtain a device number for the device
	device_number = register_chrdev(0, DEVICE_NAME, &fo);
	if(device_number < 0) {
		printk(KERN_ALERT "cryptodev: Error while trying to register a major number\n");
		return device_number;
	}
	printk(KERN_INFO "cryptodev: New device successfully registered with major number: %d\n", device_number);

	// Now we can register the device class...
	cryptodev_class = class_create(THIS_MODULE, DEVICE_CLASS);
	if(IS_ERR(cryptodev_class)) { // In case of errors, just abort 
		unregister_chrdev(device_number, DEVICE_NAME);
		printk(KERN_ALERT "Failed to register device class\n");
		return PTR_ERR(cryptodev_class);
	}
	printk(KERN_INFO "cryptodev: device class successfully created\n");

	//...and the device driver
	cryptodev_device = device_create(cryptodev_class, NULL, MKDEV(device_number, 0), NULL, DEVICE_NAME);
	if(IS_ERR(cryptodev_device)) { // In case of errors, just abort
		class_destroy(cryptodev_class);
		unregister_chrdev(device_number, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create a new device\n");
		return PTR_ERR(cryptodev_device);
	}
	printk(KERN_INFO "cryptodev: device driver successfully created\n");
	return 0;
}

static void __exit cryptodev_exit(void) {
	device_destroy(cryptodev_class, MKDEV(device_number, 0)); // Remove the device
	class_unregister(cryptodev_class); // Unregister class
	class_destroy(cryptodev_class); // Destroy the class
	unregister_chrdev(device_number, DEVICE_NAME); // Unregister device's major number
	printk(KERN_INFO "cryptodev: Module unloaded successfully\n");
}

/* This function is being called each time an userspace process
 * tries to open the character device, since we do not have anything
 * to setup, we'll just increment a counter */
static int cryptodev_open(struct inode *inodep, struct file *filep) {
	open_count++;
	printk(KERN_INFO "cryptodev: this device has been opened %d times\n", open_count);
	return 0;
}

/* This function is being called each time an userspace process
 * release the character device 
 * Since we do not have anything to do, we just log the user about it*/
static int cryptodev_close(struct inode *inodep, struct file *filep) {
	printk(KERN_INFO "cryptodev: Device successfully closed\n");
	return 0;
}

/* This function is being called each time an userspace process
 * tries to read from the device, in these cases we use the 
 * 'copy_to_user' method to send the buffer string to the user. 
 * Process may call this function to return encrypted/decrypted data */
static ssize_t cryptodev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
	// Always use size of msg or len bytes, whichever is less
	size_t bytes_to_copy = (len >= size_of_msg) ? size_of_msg : len;
	size_t bytes_not_copied = 0;

	// If msg is empty just return
	if(!bytes_to_copy)
		return 0;
	/* copy_to_user method returns 0 if successful,
	 * else it returns the number of bytes not copied */
	bytes_not_copied = copy_to_user(buffer, hashed_data, 16);
	if(bytes_to_copy - bytes_not_copied)
		printk(KERN_INFO "cryptodev: Sent %ld bytes to the user\n", (bytes_to_copy- bytes_not_copied));
	else if(bytes_not_copied) {
		printk(KERN_WARNING "cryptodev: Failed to send %ld character to userspace\n", bytes_not_copied);
		return -EFAULT;
	}
	size_of_msg = 0;

	return 0;
}


/* This function is being used each time an userspace process
 * tries to write to the device, here we retrieve user data
 * and we encrypt/decrypt using Linux kernel crypto APIs */
static ssize_t cryptodev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
	/* First of all, we need to compute
	 * the max length for sprintf(which is 14),
	 * we also need to reserve one more byte for the NULL terminator */
	const size_t max_len = 256 - 14 - 1;
	size_t bytes_to_copy = (len >= max_len) ? max_len : len; // If len is > 255, copy only first 255 bytes
	size_t bytes_not_copied = 0;
	// Crypto structs and variables
	struct crypto_shash *algorithm;
	struct shash_desc *desc;

	/* copy_from_user returns 0 if successful
	 * else it returns number of bytes not copied */
	bytes_not_copied = copy_from_user(userspace_msg, buffer, bytes_to_copy);
	size_of_msg = bytes_to_copy - bytes_not_copied +1; // Add null terminator
	printk(KERN_INFO "cryptodev: Received %zu character from userspace\n", bytes_to_copy - bytes_not_copied);
	if(bytes_not_copied) {
		printk(KERN_WARNING "cryptodev: Failed to read %zu characters, returning -EFAULT\n", bytes_not_copied);
		return -EFAULT;
	}

	/* Once data has been received, we can start
	 * to setup hashing structs and variables */
	// Define which algorithm to use
	algorithm = crypto_alloc_shash("md5", 0, 0);
	
	// Check if md5 is available
	if(IS_ERR(algorithm)) {
		printk(KERN_ALERT "cryptodev: MD5 crypto not found on this kernel, this is a problem\n");
		return -EFAULT;
	}

	desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(algorithm), GFP_KERNEL);
	// Check kmalloc
	if(!desc) {
		printk(KERN_ERR "Failed to allocate heap memory\n");
		return -ENOMEM;
	}
	// Assign choosen algorithm to tfm
	desc->tfm = algorithm;

	// Init choosen algorithm
	if(crypto_shash_init(desc)) { // Exit gracefully
		printk(KERN_WARNING "Failed to initialize message digest\n");
		crypto_free_shash(algorithm);
		kfree(algorithm);
		return -EFAULT;	
	}

	// Execute hash function
	if(crypto_shash_update(desc, userspace_msg, strlen(userspace_msg))) { // Exit gracefully
		printk(KERN_WARNING "Failed to execute crypto function\n");
		crypto_free_shash(algorithm);
		kfree(algorithm);
		return -EFAULT;	
	}
	if(crypto_shash_final(desc, hashed_data)) { // Exit gracefully
		printk(KERN_WARNING "Failed to complete digest operation\n");
		crypto_free_shash(algorithm);
		kfree(algorithm);
		return -EFAULT;
	}
	// Finally, clean used memory
	crypto_free_shash(algorithm);
	kfree(desc);

	printk(KERN_INFO "cryptodev: Hashing operation completed successfully\n");

	return 0;
}


// Finally, register __init and __exit functions using macros
module_init(cryptodev_init);
module_exit(cryptodev_exit);
