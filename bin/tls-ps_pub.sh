export LD_LIBRARY_PATH=/home/hwlee/drive/tls-ps/tlsps-lib:/home/hwlee/drive/tls-ps/openssl/lib
./mosquitto_tlsps_pub -t hello -m test --cafile ../certs/demoCA/cacert.pem -h www.rsa.com --key ../certs/publisher_priv.pem --cert ../certs/publisher_pub.pem
