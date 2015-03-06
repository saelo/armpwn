as = arm-none-eabi-as
objcopy = arm-none-eabi-objcopy

all: shellcode.arm shellcode.thumb

shellcode.arm: shellcode.arm.S
	$(as) -o shellcode.o shellcode.arm.S
	$(objcopy) -O binary shellcode.o shellcode.arm
	rm shellcode.o

shellcode.thumb: shellcode.thumb.S
	$(as) -mthumb -o shellcode.o shellcode.thumb.S
	$(objcopy) -O binary shellcode.o shellcode.thumb
	rm shellcode.o

clean:
	rm shellcode.arm
	rm shellcode.thumb
