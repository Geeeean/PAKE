CC = gcc

SOURCEDIR  = src
BUILDDIR   = build
BINDIR     = bin
INCLUDEDIR = include

CLIENT = client
SERVER = server
CORE   = core

CORE_IFLAGS   = -I$(INCLUDEDIR)/$(CORE)
CLIENT_IFLAGS = -I$(INCLUDEDIR)/$(CLIENT) $(CORE_IFLAGS)
SERVER_IFLAGS = -I$(INCLUDEDIR)/$(SERVER) $(CORE_IFLAGS)

CLIENT_SOURCES := $(wildcard $(SOURCEDIR)/$(CLIENT)/*.c) $(wildcard $(SOURCEDIR)/$(CORE)/*.c)
SERVER_SOURCES := $(wildcard $(SOURCEDIR)/$(SERVER)/*.c) $(wildcard $(SOURCEDIR)/$(CORE)/*.c)
CLIENT_OBJS := $(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/%.o, $(CLIENT_SOURCES))
SERVER_OBJS := $(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/%.o, $(SERVER_SOURCES))

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

.PHONY: clean

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
