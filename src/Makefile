netrogue: test.o packet.o sniff.o attack.o helper.o
	gcc -o netrogue test.o packet.o sniff.o attack.o helper.o

test.o: test.c helper.h attack.h
	gcc -c test.c

packet.o: packet.c packet.h helper.h
	gcc -c packet.c

sniff.o: sniff.c sniff.h helper.h
	gcc -c sniff.c

attack.o: attack.c attack.h helper.h sniff.h packet.h
	gcc -c attack.c

helper.o: helper.c helper.h
	gcc -c helper.c