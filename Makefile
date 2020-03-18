all:
	gcc -o main main.c encrypt.cpp sm3.c sm4.c transform.cpp log.cpp
clean:
	rm main
