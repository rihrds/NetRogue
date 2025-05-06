netrogue: netrogue.o packet.o sniff.o owe_attacks.o helper.o pmkid_attack.o twin_ap_attack.o
	gcc -o netrogue netrogue.o packet.o sniff.o owe_attacks.o helper.o pmkid_attack.o twin_ap_attack.o

netrogue.o: netrogue.c helper.h owe_attacks.h pmkid_attack.h twin_ap_attack.h
	gcc -c netrogue.c

packet.o: packet.c packet.h helper.h
	gcc -c packet.c

sniff.o: sniff.c sniff.h helper.h
	gcc -c sniff.c

owe_attacks.o: owe_attacks.c owe_attacks.h helper.h sniff.h packet.h
	gcc -c owe_attacks.c

helper.o: helper.c helper.h
	gcc -c helper.c

pmkid_attack.o: pmkid_attack.c pmkid_attack.h
	gcc -c pmkid_attack.c

twin_ap_attack.o: twin_ap_attack.c twin_ap_attack.h
	gcc -c twin_ap_attack.c