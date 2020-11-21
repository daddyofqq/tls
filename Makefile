CXX = g++
CC = gcc

ROOTDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
OBJDIR := $(CURDIR)/build

# cryptoecc/test/sha3/sha3.c

SRCS = native/client-test.cpp alg/alg.cpp  $(wildcard alg/mbedtls/*.c) $(wildcard x509/*.cpp)

OBJS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(patsubst %.c, $(OBJDIR)/%.o, $(SRCS)))

#-O3
CFLAGS := $(CFLAGS) -I. -I./cryptoecc -I./alg -I./x509 -I./native -DUSE_SECURE_ALLOCATOR -DHAVE_LOG -g -Werror

CPPFLAGS := $(CFLAGS) -std=c++17

all: $(OBJDIR)/client

$(OBJDIR)/client: $(OBJS)
	@echo "LD $@"
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -pthread -o $@ $^

$(OBJDIR)/%.o: $(ROOTDIR)/%.cpp $(OBJDIR)/%.d
	@echo "CXX $<"
	@mkdir -p $(dir $@)
	@$(CXX) -c $(DEPFLAGS) $(CPPFLAGS) -o $@ -c $< $(INCLUDES)

$(OBJDIR)/%.o: $(ROOTDIR)/%.c $(OBJDIR)/%.d
	@echo "CC $(LTO) $<"
	@mkdir -p $(dir $@)
	@$(CC) -c $(DEPFLAGS) $(CFLAGS) -o $@ -c $< $(INCLUDES)

$(OBJDIR):
	@mkdir -p $@

$(OBJDIR)/%.d: ;
.PRECIOUS: $(OBJDIR)/%.d

-include $(patsubst %.o, %.d, $(OBJS))

clean:
	rm -rf build
