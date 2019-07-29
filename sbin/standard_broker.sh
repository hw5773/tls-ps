PWD=`pwd`
export LD_LIBRARY_PATH=$PWD/../lib:/usr/local/lib
./mosquitto -c ../conf/mosquitto.conf
