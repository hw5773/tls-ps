PWD=`pwd`
export LD_LIBRARY_PATH=$PWD/../lib:/usr/local/lib
./mosquitto_sub -t hello --cafile ../certs/demoCA/cacert.pem -h www.rsa.com --key ../certs/subscriber_priv.pem --cert ../certs/subscriber_pub.pem
