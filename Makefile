
# c compiler
CC = gcc

# assembler
ASM = nasm

# assembler flags
AFLAGS = -f win64

.PHONY: clean

arpe: arpe.obj
	$(CC) arpe.obj -o arpe

arpe.obj: arpe.asm
	$(ASM) $(AFLAGS) arpe.asm

clean:
	rm -f *.obj *.exe



