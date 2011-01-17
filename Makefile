CC = gcc
LIBS = -lm -lcrypto
CFLAGS = -Wall
OBJECTS = depkgapp.o

depkgapp : $(OBJECTS)
	$(CC) $(LIBS) $(CFLAGS) $(OBJECTS) -o depkgapp

%.o : $.c
	$(CC) $(LIBS) $(CFLAGS) -c $<

clean:
	@rm $(OBJECTS) 
