DATABASE_DIR = ./database/
OBJECTS_DIR = ./obj/
EXECS_DIR = ./exec/
TEMP_DIR = ./temp/

HEADERS_DIR = ./header/
AUXCODE_DIR = ./auxcode/
MAINCODE_DIR = ./main/

all: make_objs
	g++ $(OBJECTS_DIR)client.o $(OBJECTS_DIR)client_aux.o $(OBJECTS_DIR)common_aux.o $(OBJECTS_DIR)tls_aux.o -o $(EXECS_DIR)client.out -lssl -lcrypto -std=c++11
	g++ $(OBJECTS_DIR)server.o $(OBJECTS_DIR)server_aux.o $(OBJECTS_DIR)common_aux.o -o $(EXECS_DIR)server.out -lssl -lcrypto -std=c++11
	g++ $(OBJECTS_DIR)ca.o $(OBJECTS_DIR)common_aux.o -o $(EXECS_DIR)ca.out -std=c++11
	###########################################################
	# Please change directory to ./exec before running any ".out" file #

make_objs: make_dirs obj1 obj2 obj3 obj4 obj5 obj6 obj7


obj1: $(AUXCODE_DIR)client_aux.cpp
	g++ -c $(AUXCODE_DIR)client_aux.cpp -o $(OBJECTS_DIR)client_aux.o -std=c++11

obj2: $(AUXCODE_DIR)common_aux.cpp
	g++ -c $(AUXCODE_DIR)common_aux.cpp -o $(OBJECTS_DIR)common_aux.o -std=c++11

obj3: $(AUXCODE_DIR)tls_aux.cpp
	g++ -c $(AUXCODE_DIR)tls_aux.cpp -o $(OBJECTS_DIR)tls_aux.o -std=c++11

obj4: $(AUXCODE_DIR)server_aux.cpp
	g++ -c $(AUXCODE_DIR)server_aux.cpp -o $(OBJECTS_DIR)server_aux.o -std=c++11

obj5: $(MAINCODE_DIR)client.cpp
	g++ -c $(MAINCODE_DIR)client.cpp -o $(OBJECTS_DIR)client.o -std=c++11

obj6: $(MAINCODE_DIR)server.cpp
	g++ -c $(MAINCODE_DIR)server.cpp -o $(OBJECTS_DIR)server.o -std=c++11

obj7: $(MAINCODE_DIR)ca.cpp
	g++ -c $(MAINCODE_DIR)ca.cpp -o $(OBJECTS_DIR)ca.o -std=c++11

make_dirs:
	if [ ! -d $(DATABASE_DIR) ]; then mkdir $(DATABASE_DIR); fi;
	if [ ! -d $(OBJECTS_DIR) ]; then mkdir $(OBJECTS_DIR); fi;
	if [ ! -d $(EXECS_DIR) ]; then mkdir $(EXECS_DIR); fi;
	if [ ! -d $(TEMP_DIR) ]; then mkdir $(TEMP_DIR); fi;

clean:
	if [ -d $(DATABASE_DIR) ]; then rm -rf $(DATABASE_DIR); fi;
	if [ -d $(OBJECTS_DIR) ]; then rm -rf $(OBJECTS_DIR); fi;
	if [ -d $(EXECS_DIR) ]; then rm -rf $(EXECS_DIR); fi;
	if [ -d $(TEMP_DIR) ]; then rm -rf $(TEMP_DIR); fi;
