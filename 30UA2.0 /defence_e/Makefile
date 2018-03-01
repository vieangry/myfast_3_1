
client_LDADD = -L ../include -L ../libreg\
	-L../librule \
	-L../libua \
	-lrule \
	-lua \
	-lreg \
	-lpthread

object=defence_e.o net.o

defence_e:defence_e.o net.o
	gcc -o defence_e $(object) $(client_LDADD)
defence_e.o:defence_e.c
	gcc -c  defence_e.c $(client_LDADD)
net.o:net.c net.h
	gcc -c net.c
clean:
	rm defence_e $(object)
