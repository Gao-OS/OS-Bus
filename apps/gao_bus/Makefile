CC ?= cc
CFLAGS ?= -O2
NIF = $(MIX_APP_PATH)/priv/gao_unix.so
BRIDGE = $(MIX_APP_PATH)/priv/gao_helper_bridge
# Immutable package-time installed entrypoint. Unset builds fail closed.
GAO_HELPER_PATH ?=
BRIDGE_BINDING = $(if $(GAO_HELPER_PATH),-DGAO_HELPER_PATH='"$(GAO_HELPER_PATH)"')

.PHONY: all clean bridge-binding
all: $(NIF) $(BRIDGE)

$(BRIDGE): c_src/gao_helper_bridge.c bridge-binding
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -fstack-protector-strong $(BRIDGE_BINDING) -Wl,-z,relro,-z,now -o $@ $<

$(NIF): c_src/gao_unix.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -fPIC -fstack-protector-strong -I$(ERTS_INCLUDE_DIR) -shared -Wl,-z,relro,-z,now -o $@ $<

clean:
	rm -f $(NIF) $(BRIDGE)
