DIRS = hello callgraph taint vararg struct memcpy phi interdepend gep addr graph alias core point malloc

define runall
	@for d in $(DIRS); do \
	  echo -e "\n==================================================="; \
	  echo "[*] $1 $$d"; \
	  $(MAKE) --no-print-directory -C $$d $2; \
	done
endef

all:
	$(call runall,"Building")

run:
	$(call runall,"Running",run)

clean:
	$(call runall,"Cleaning",clean)

.PHONY: all test run clean
