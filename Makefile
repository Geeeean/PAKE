CC = gcc

SOURCEDIR  = src
BUILDDIR   = build
BINDIR     = bin
INCLUDEDIR = include
TESTDIR    = test

CLIENT = client
SERVER = server
CORE   = core
TEST   = test

CORE_IFLAGS   = -I$(INCLUDEDIR)/$(CORE)
CLIENT_IFLAGS = -I$(INCLUDEDIR) $(CORE_IFLAGS)
SERVER_IFLAGS = -I$(INCLUDEDIR) $(CORE_IFLAGS)
TEST_IFLAGS   = -I$(INCLUDEDIR) -I$(TESTDIR) $(CORE_IFLAGS) -I$(INCLUDEDIR)/$(SERVER)

CLIENT_SOURCES := $(wildcard $(SOURCEDIR)/$(CLIENT)/*.c) $(wildcard $(SOURCEDIR)/$(CORE)/*.c)
SERVER_SOURCES := $(wildcard $(SOURCEDIR)/$(SERVER)/*.c) $(wildcard $(SOURCEDIR)/$(CORE)/*.c)
TEST_SOURCES   := $(TESTDIR)/unity.c $(TESTDIR)/main.c $(wildcard $(SOURCEDIR)/$(CORE)/*.c) $(SOURCEDIR)/$(SERVER)/server.c $(SOURCEDIR)/$(SERVER)/storage.c $(SOURCEDIR)/$(CLIENT)/client.c
CLIENT_OBJS := $(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/%.o, $(CLIENT_SOURCES))
SERVER_OBJS := $(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/%.o, $(SERVER_SOURCES))
TEST_OBJS   := $(patsubst $(TESTDIR)/%.c, $(BUILDDIR)/$(TESTDIR)/%.o, $(TEST_SOURCES))

LIBS = sodium
LLIBS := $(patsubst %,-l%,$(LIBS))

all: $(CLIENT) $(SERVER)

$(CLIENT): $(BINDIR)/$(CLIENT)
$(SERVER): $(BINDIR)/$(SERVER)

# Client objs
$(BUILDDIR)/$(CLIENT)/%.o: $(SOURCEDIR)/$(CLIENT)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CLIENT_IFLAGS)

# Server objs
$(BUILDDIR)/$(SERVER)/%.o: $(SOURCEDIR)/$(SERVER)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(SERVER_IFLAGS)

# Core objs
$(BUILDDIR)/$(CORE)/%.o: $(SOURCEDIR)/$(CORE)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CORE_IFLAGS)

# Client bin
$(BINDIR)/$(CLIENT): $(CLIENT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $^ $(LFLAGS) $(LLIBS)

# Server bin
$(BINDIR)/$(SERVER): $(SERVER_OBJS)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $^ $(LFLAGS) $(LLIBS)

# Test
$(BINDIR)/$(TEST): $(TEST_SOURCES)
	@mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(TEST_IFLAGS) $(LLIBS)

test: $(BINDIR)/$(TEST)
	@./$(BINDIR)/$(TEST)

.PHONY: clean

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
