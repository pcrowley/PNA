
MODULE := module/pna.ko
USER := user/user_monitor user/user_alerts

all: $(MODULE) $(USER)

$(MODULE):
	$(MAKE) -C module/

$(USER):
	$(MAKE) -C user/

start: $(MODULE) $(USER)
	./service/pna start

stop:
	./service/pna stop

status:
	./service/pna status

clean:
	$(MAKE) -C module clean
	$(MAKE) -C user clean
