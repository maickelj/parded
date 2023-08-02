
PKG_NAME=auditoragent
PKG_VERSION=0.0.1
PKG_RELEASE=1
PKG_BUILD_DIR=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

SRC_DIR=src



LIB=-L./$(SRC_DIR)/lib/
INCLUDE=-I./$(SRC_DIR)/include/
#-I/usr/include/libnetfilter_queue

C_SOURCE=$(wildcard ./$(SRC_DIR)/*.c)
H_SOURCE=$(wildcard ./$(SRC_DIR)/*.h)
OBJ=$(C_SOURCE:.c=.o)

CC=gcc

CC_FLAGS=-c -Wall $(INCLUDE)
LL_FLAGS=$(LIB) -letcd -lcurl -lnetfilter_queue -lnfnetlink -lmnl -lpthread -ljansson -lpq -lpcap

all: $(PKG_NAME)

$(PKG_NAME): $(OBJ)
	echo 'criando o binario com o GCC Linker'
	$(CC) -o $@ $^ $(LL_FLAGS)

%.o: %.c %.h
	@ echo 'compilando os arquivos secundarios'
	$(CC) -o $@ $< $(CC_FLAGS)

./$(SRC_DIR)/main.o: ./$(SRC_DIR)/main.c $(H_SOURCE) 
	@ echo 'compilando o arquivo principal'
	$(CC) -o $@ $< $(CC_FLAGS) 

#./$(SRC_DIR)/$(PKG_NAME).o: ./$(SRC_DIR)/$(PKG_NAME).c $(H_SOURCE) 
#	@ echo 'compilando o arquivo principal'
#	$(CC) -o $@ $< $(CC_FLAGS) 

clean:
	rm -rf ./$(SRC_DIR)/*.o *~ $(PROJ_NAME)

