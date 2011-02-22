
all:
	@echo "Specify start or stop"

start:
	sudo ./module/service start

stop:
	sudo ./module/service stop
