# exo-smart-registrator

EXO Smart Registrator C based card reader.

## Prepare development environment

```
  apt-get install libpq5 libpq-dev

  apt-get install libusb-dev libpcsclite-dev
  wget https://github.com/nfc-tools/libnfc/releases/download/libnfc-1.7.1/libnfc-1.7.1.tar.bz2
  tar -xvvjf libnfc-1.7.1.tar.bz2
  cd libnfc-1.7.1
  make install
```
In order to enable logging functionality in the system log add the following configuration line in the /etc/rsyslog.d/50-default.conf configuration file for rsyslog.

:programname,contains,"registrator" /var/log/registrator.log

### Installing

```
  ./autogen.sh
  ./configure
  make
  make install 
```

