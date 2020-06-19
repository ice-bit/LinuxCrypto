obj-m += linuxcrypto.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) userspace_interface.c -o uint
	#sudo insmod linuxcrypto.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm uint
	#sudo rmmod linuxcrypto
