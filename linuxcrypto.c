/* Loadable Kernel Module(LKM) that 
 * create a character device able
 * to encrypt strings using AES256
 * encryption. This driver uses 
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
MODULE_DESCRIPTION("Char device that encrypt/decrypt data");
MODULE_VERSION("0.1");
MODULE_LICENSE("Dual BSD/GPL");

// Definition of global variables(only available into this file)
static int device_number; // Number of character device, aka major number
static char userspace_msg[256] = {0}; // Data from userspace with fixed size
static short size_of_msg; // Actual buffer size
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
	printk(KERN_INFO "Cryptodev: Loading, please wait...\n");

	// Obtain a device number for the device
	device_number = register_chrdev(0, DEVICE_NAME, &fo);
	if(device_number < 0) {
		printk(KERN_ALERT "Cryptodev: Error while trying to register a major number\n");
		return device_number;
	}
	printk(KERN_INFO "Cryptodev: New device successfully registered with major number: %d\n", device_number);

	// Now we can register the device class...
	cryptodev_class = class_create(THIS_MODULE, DEVICE_CLASS);
	if(IS_ERR(cryptodev_class)) { // In case of errors, just abort 
		unregister_chrdev(device_number, DEVICE_NAME);
		printk(KERN_ALERT "Failed to register device class\n");
		return PTR_ERR(cryptodev_class);
	}
	printk(KERN_INFO "Cryptodev: device class successfully created\n");

	//...and the device driver
	cryptodev_device = device_create(cryptodev_class, NULL, MKDEV(device_number, 0), NULL, DEVICE_NAME);
	if(IS_ERR(cryptodev_device)) { // In case of errors, just abort
		class_destroy(cryptodev_class);
		unregister_chrdev(device_number, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create a new device\n");
		return PTR_ERR(cryptodev_device);
	}
	printk(KERN_INFO "Cryptodev: device class successfully created\n");
	return 0;
}

static void __exit cryptodev_exit(void) {
	device_destroy(cryptodev_class, MKDEV(device_number, 0)); // Remove the device
	class_unregister(cryptodev_class); // Unregister class
	class_destroy(cryptodev_class); // Destroy the class
	unregister_chrdev(device_number, DEVICE_NAME); // Unregister device's major number
	printk(KERN_INFO "Cryptodev: Module unloaded successfully\n");
}

/* This function is being called each time an userspace process
 * tries to open the character device, since we do not have anything
 * to setup, we'll just increment a counter */
static int cryptodev_open(struct inode *inodep, struct file *filep) {
	open_count++;
	printk(KERN_INFO "Cryptodev: this device has been opened %d times\n", open_count);
	return 0;
}

/* This function is being called each time an userspace process
 * release the character device 
 * Since we do not have anything to do, we just log the user about it*/
static int cryptodev_close(struct inode *inodep, struct file *filep) {
	printk(KERN_INFO "Cryptodev: Device successfully closed\n");
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
	bytes_not_copied = copy_to_user(buffer, userspace_msg, bytes_to_copy);
	if(bytes_to_copy - bytes_not_copied)
		printk(KERN_INFO "Cryptodev: Sent %ld bytes to the user\n", (bytes_to_copy- bytes_not_copied));
	else if(bytes_not_copied) {
		printk(KERN_WARNING "Cryptodev: Failed to send %ld character to userspace\n", bytes_not_copied);
		return -EFAULT;
	}
	size_of_msg = 0;
	return bytes_to_copy;
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
	struct shash_desc *algorithm;
	char *hashed_data = NULL; // Result of hash function
	int err;
	algorithm = kmalloc(sizeof(*algorithm), GFP_KERNEL);

	/* copy_from_user returns 0 if successful
	 * else it returns number of bytes not copied */
	bytes_not_copied = copy_from_user(userspace_msg, buffer, bytes_to_copy);
	sprintf(userspace_msg + bytes_to_copy - bytes_not_copied, " (%zu letters)", bytes_to_copy - bytes_not_copied);
	size_of_msg = bytes_to_copy - bytes_not_copied +1; // Add null terminator
	printk(KERN_INFO "Cryptodev: Received %zu character from userspace\n", bytes_to_copy - bytes_not_copied);
	if(bytes_not_copied) {
		printk(KERN_WARNING "Cryptodev: Failed to read %zu characters, returning -EFAULT\n", bytes_not_copied);
		return -EFAULT;
	}
	
	/* Once data has been received, we can start
	 * to setup hashing structs and variables */
	// Define which algorithm to use
	algorithm->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC); 

	/* However it's not obvious that md5 algorithm 
	 * is available in your Kernel. So to be sure
	 * we have to check if it is NULL. To obtain 
	 * a full list of available crypto algorithms 
	 * on your kernel, just cat /proc/crypto device */
	if(algorithm->tfm == NULL) {
		printk(KERN_ALERT "Cryptodev: MD5 crypto not found on this kerne, this is a problem\n");
		return -EIO;
	}

	// Otherwise just init choosen algorithm...
	err = crypto_shash_init(algorithm);
	if(err) { // Exit gracefully
		printk(KERN_WARNING "Failed to initialize message digest\n");
		crypto_free_shash(algorithm->tfm);
		kfree(algorithm);
		return err;	
	}
	// ...And execute hash function
	err = crypto_shash_update(algorithm, userspace_msg, size_of_msg);
	if(err) { // Exit gracefully
		printk(KERN_WARNING "Failed to execute crypto function\n");
		crypto_free_shash(algorithm->tfm);
		kfree(algorithm);
		return err;	
	}
	err = crypto_shash_final(algorithm, hashed_data);
	if(err) { // Exit gracefully
		printk(KERN_WARNING "Failed to complete digest operation\n");
		crypto_free_shash(algorithm->tfm);
		kfree(algorithm);
		return err;
	}
	// Finally, clean used memory
	crypto_free_shash(algorithm->tfm);
	kfree(algorithm);

	printk(KERN_INFO "Cryptodev: Hashing operation completed successfully\n");

	return bytes_to_copy;
}


// Finally, register __init and __exit functions using macros
module_init(cryptodev_init);
module_exit(cryptodev_exit);
