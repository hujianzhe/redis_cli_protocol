SOURCE_C_FILE += $(shell find . -name "*.c")
SOURCE_CPP_FILE += $(shell find . -name "*.cpp")

TARGET_PATH += .
COMPILE_OPTION := -fPIC -shared -Wno-deprecated -Wno-parentheses
MACRO := -D_REENTRANT

DEFAULT_LINK :=

COMPILER := gcc
ifeq ($(COMPILER), gcc)
SOURCE_CPP_FILE :=
endif

DEBUG_TARGET := $(TARGET_PATH)/libRedisCliProtocolDynamicDebug.so
RELEASE_TARGET := $(TARGET_PATH)/libRedisCliProtocolDynamic.so

all:

debug:
	$(COMPILER) $(MACRO) -D_DEBUG -g $(COMPILE_OPTION) $(SOURCE_C_FILE) $(SOURCE_CPP_FILE) -o $(DEBUG_TARGET) $(DEFAULT_LINK)

release:
	$(COMPILER) $(MACRO) -DNDEBUG -O1 $(COMPILE_OPTION) $(SOURCE_C_FILE) $(SOURCE_CPP_FILE) -o $(RELEASE_TARGET) $(DEFAULT_LINK)
