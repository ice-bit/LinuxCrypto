obj-m += linuxcrypto.o
CFLAGS = -Wall -Wextra -Werror -std=c99

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) $(CFLAGS) userspace_interface.c -o uint

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm uint
