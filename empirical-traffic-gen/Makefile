
all: tcp
	
tcp: export DIR=src
tcp:
	$(MAKE) compile

udp: export DIR=src_udp
udp:
	$(MAKE) compile

compile:
	cd ./$(DIR); $(MAKE); cd ..;
	rm -rf bin
	mkdir bin
	cp ./$(DIR)/client bin/.
	cp ./$(DIR)/server bin/.

clean: 
	cd src; $(MAKE) clean; cd ..;
	cd src_udp; $(MAKE) clean; cd ..;
	rm -rf bin

