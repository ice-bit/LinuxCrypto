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
_work in progres_

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
