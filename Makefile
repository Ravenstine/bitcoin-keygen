default: bitcoin-keygen

all: bitcoin-keygen install

bitcoin-keygen:
	gcc -o bitcoin-keygen bitcoin-keygen.c $(shell pkg-config --cflags --libs openssl libqrencode)

install:
	cp bitcoin-keygen /usr/bin/bitcoin-keygen

clean:
	rm -f bitcoin-keygen

image:
	docker build -t bitcoin-keygen .

container:
	docker run --rm --network none bitcoin-keygen
