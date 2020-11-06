.PHONY: all

all:
	$(MAKE) -C go/
	$(MAKE) -C python/
	diff go.out python.out
