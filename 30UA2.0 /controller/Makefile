object=controller.o net.o data_struct.o

main:controller.o net.o data_struct.o
	g++ -o main $(object)

controller.o:controller.cpp comm.h net.h data_struct.h
	g++ -c controller.cpp
data_struct.o:data_struct.cpp data_struct.h
	g++ -c data_struct.cpp
net.o:net.cpp net.h
	g++ -c net.cpp

clean:
	rm main *.o
