# user-space programs
user-monitor := user_monitor
user-alerts := user_alerts
user-progs := $(user-monitor) $(user-alerts)

CFLAGS += -I../include/

all: $(user-progs)

$(user-monitor): $(user-monitor).c
	$(CC) $(CFLAGS) -o $@ $^

$(user-alerts): $(user-alerts).c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(user-progs)
