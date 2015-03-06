CC=gcc
CFLAGS=-std=gnu99 -fstack-protector -fPIE -pie -z relro -z now -O1
TARGET=websrv
SRC=websrv.c

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) -o $@ $<
	strip $(TARGET)
	sudo setcap 'cap_net_bind_service=+ep' $(TARGET)

clean:
	rm $(TARGET)

