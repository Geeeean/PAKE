CC = gcc
IFLAGS = -I$(IDIR) -I$(LDIR)
ifeq ($(wildcard $(LDIR)),)
  LFLAGS :=
else
  LFLAGS = -L$(LDIR)
endif

SRCDIR = src
IDIR = include
BUILDDIR = build
BINDIR = bin
LDIR = lib
LIBS = libsodium.a
LLIBS := $(patsubst lib%.a,-l%,$(LIBS)) 

TARGET = pake

LOCAL_DEPS := $(wildcard $(IDIR)/*.h)
LIB_DEPS := $(wildcard $(LDIR)/*/*.h)
DEPS := $(LOCAL_DEPS) $(LIB_DEPS)

LOCAL_SOURCES := $(wildcard $(SRCDIR)/*.c)
LIB_SOURCES := $(wildcard $(LDIR)/*/*.c)
SOURCES := $(LOCAL_SOURCES) $(LIB_SOURCES)
OBJ = $(patsubst %.c,$(BUILDDIR)/%.o, $(SOURCES))

$(TARGET): $(OBJ)
	@mkdir -p $(BINDIR)
	$(CC) -o $(BINDIR)/$@ $^ $(LFLAGS) $(LLIBS)

$(BUILDDIR)/%.o: %.c $(DEPS)
	@ mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(IFLAGS)

.PHONY: clean

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
