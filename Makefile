all : panthercrypt.c pantherdec.c

	gcc -o panthercrypt panthercrypt.c $(libgcrypt-config --cflags --libs)

