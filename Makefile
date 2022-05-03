CC=clang
CFLAGS = -std=c11 -Wall -pedantic -Iinclude -Wall -g -fsanitize=address
SRC_FILES = $(wildcard src/*.c)  $(wildcard src/*/*.c)
FILES = $(basename $(SRC_FILES:src/%=%))
OBJ_FILES = $(addprefix obj/,$(FILES:=.o))
TEST_FILES = $(join $(dir $(addprefix bin/tests/,$(FILES))), $(addprefix test_,$(notdir $(FILES))))
VERSION = 0.1.0

RWILDCARD = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

# module variables
MODULES := git@github.com:thomasbarrett/uint.git@v0.1.0
MODULES_REPOSITORY := $(addprefix git@, $(foreach dep, $(MODULES), $(word 2, $(subst @, ,$(dep)))))
MODULES_VERSION := $(foreach dep, $(MODULES), $(word 3, $(subst @, ,$(dep))))
MODULES_MAJOR_VERSION := $(foreach dep, $(MODULES_VERSION), $(word 1, $(subst ., ,$(dep))))
MODULES_PREFIX := /tmp/.modules/
MODULES_ROOT := $(foreach dep, $(MODULES_REPOSITORY), $(word 1, $(subst ., ,$(word 2, $(subst :, ,$(dep))))))
MODULES_PATH := $(addprefix $(MODULES_PREFIX), $(join $(MODULES_ROOT), $(addprefix /,$(MODULES_MAJOR_VERSION))))
MODULES_INCLUDE := $(foreach p, $(MODULES_PATH), -I$(p:=/include))
MODULES_OBJ = $(foreach p, $(MODULES_PATH), $(addprefix $p/, $(shell $(MAKE) object-files -C $p 2>/dev/null)))

.PHONY: all 
all: bin/server bin/client $(TEST_FILES) $(OBJ_FILES)

.PHONY: clean
clean:
	@rm -rf obj
	@rm -rf bin

$(MODULES_OBJ): build-deps

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	@$(CC) -c $(CFLAGS) $(MODULES_INCLUDE) $^ -o $@

bin/tests/%: tests/%.c $(OBJ_FILES) $(MODULES_OBJ)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(MODULES_INCLUDE) $^ -o $@

bin/server: main/server.c $(OBJ_FILES) $(MODULES_OBJ)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(MODULES_INCLUDE) $^ -o $@

bin/client: main/client.c $(OBJ_FILES) $(MODULES_OBJ)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(MODULES_INCLUDE) $^ -o $@

.PHONY: test
test: $(TEST_FILES)
	tests/run.sh $(TEST_FILES)

.PHONY: version
version:
	@echo ${VERSION}

.PHONY: list-deps
list-deps:
	@echo $(MODULES)


	
# suppress error for missing test file
bin/tests/%:
	@:
	
.PHONY: install-deps
install-deps:
	@$(foreach i, $(shell seq 1 $(words $(MODULES))), \
		M_PATH=$(word $i, $(MODULES_PATH)); \
		M_ROOT=$(word $i, $(MODULES_ROOT)); \
		M_REPOSITORY=$(word $i, $(MODULES_REPOSITORY)); \
		M_VERSION=$(word $i, $(MODULES_VERSION)); \
		if [ ! -d "$${M_PATH}" ]; then \
			printf "[ %s ] %s\n" $${M_VERSION} $${M_ROOT}; \
 			git clone "$${M_REPOSITORY}" --branch $${M_VERSION} --single-branch $${M_PATH} 2> /dev/null; \
		fi \
	)

# The build-deps target builds all dependency module makefiles 
.PHONY: build-deps
build-deps: install-deps
	@$(foreach i, $(shell seq 1 $(words $(MODULES))), \
		M_PATH=$(word $i, $(MODULES_PATH)); \
		M_VERSION=$(word $i, $(MODULES_VERSION)); \
		M_ROOT=$(word $i, $(MODULES_ROOT)); \
		printf "[ %s ] %s\n" $${M_VERSION} $${M_ROOT}; \
		$(MAKE) -C $${M_PATH} &> /dev/null; \
	)

.PHONY: lint
lint:
	@for file in $(SRC_FILES); do \
		clang-tidy $$file --checks=clang-analyzer-*,performance-* -- $(CFLAGS); \
	done