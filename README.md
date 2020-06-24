# LinuxCrypto

LinuxCrypto is a _Loadable Kernel Module_(**LKM**) that encrypt/decrypt data 
sent from userspace. It uses Linux Crypto APIs to perform MD5 hashing.  
This driver is not intended to be used on production environments, it's just a toy project.

## Building
In order to build this module you will need a proper development environment, such as:  
- GCC compiler;  
- Linux kernel source(from [here](https://kernel.org));  

There're two ways to try this module: using `insmod` or by rebuilding the whole kernel(_not recommended_)

### Using insmod
First of all compile the module using `make all`, then run:  
```
sudo insmod linuxcrypto.ko
```
When you're done using it, just run:  
```
sudo rmmod linuxcrypto
```
and clean current directory using `make clean`.

### Rebuilding the kernel
Another way to test this driver is by recompiling the whole kernel(_not recommended_):  
1. First download kernel source from [kernel.org](http://kernel.org) and unpack it using `tar xvf linux-x.y.z.tar.xz`;  
2. Create a new directory named `drivers/linuxcrypto` and place `linuxcrypto.c` in it;  
3. Create a `Kconfig` file with the following:  
    ```
        config LINUXCRYPTO
        tristate "MD5 Hash"
        depends on CRYPTO_MD5
        help
            Hash a string using MD5
    ```
4. Create a `Makefile` file with `obj-$(CONFIG_LINUXCRYPTO) += linuxcrypto.o`;  
5. Edit `drivers/Kconfig` and add `source "drivers/linuxcrypto/Kconfig"`;  
6. Edit `drivers/Makefile` and add `obj-$(CONFIG_LINUXCRYPTO) += linuxcrypto/`;  
7. Run `make menuconfig` and enable `drivers/linuxcrypto`;  
8. Run `make -j#<number of cores>`;  
9. Run `make modules_install`;  
10. Copy kernel image by running `cp -v arch/x86_64/boot/bzImage /boot/vmlinuz-linux<xyz>`;  
11. Generate initial ram disk(for instance, on Arch Linux: `mkinitcpio -p linux<xyz>`);  
12. Update bootloader config file.  

## Usage
Linux kernel module logs directly to tty, so if you have a running X environment
you should use `dmesg` to see its output:  
```
sudo dmesg -Hw
```

After that you can run(for instane on another terminal) `uint` tool to hash a sample string:   
```
marco@devserver:~/LinuxCrypto$ sudo ./uint
Opening character device...
Insert a string: Hello World
Hashing string, please wait...
Original: 'Hello World', MD5 digest: 'b10a8db164e0754105b7a99be72e3fe5'
``` 
The final output should be the same as: `echo -n "Hello World" | md5sum`


## License
[GPL](https://choosealicense.com/licenses/gpl-3.0/)
