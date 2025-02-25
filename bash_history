ls
df -h
sudo
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
ls
tar -xvf pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz 
ls
cd pin-3.28-98749-g6643ecee5-gcc-linux/
ls
cd ..
ls
git clone
ls 
git clone https://github.com/aclements/memtrace.git
ls
cd memtrace/
ls
df -h
ls
vi memtrace.cpp 
cd ..
ls
mv memtrace.cpp memtrace
mv script.sh memtrace/
cd memtrace/
ls
vi memtrace.cpp 
cd ..
ls
mv dump.go memtrace/cmd/dump
ls memtrace/cmd/dump/
ls
cd memtrace/
cd ,,
cd ..
ls
mkdir CPU2006
cd CPU2006/
ls
mkdir 429.mcf
cd 429.mcf/
ls
cd ../..
ls
mv inp.* CPU2006/429.mcf/
mv mcf* CPU2006/429.mcf/
ls
mv speccmds.* CPU2006/429.mcf/
cd memtrace/
ls
vi script.sh 
pwd
vi script.sh 
ls ../pin-3.28-98749-g6643ecee5-gcc-linux
cd ..
ls
mv pin-3.28-98749-g6643ecee5-gcc-linux pin
ls
ls pin
vi memtrace/script.sh 
vi gen_pin_cmd.py 
cd CPU2006/
ls
cd 429.mcf/
ls
cd ..
ls
mkdir run
mv 429.mcf/* run
ls run
ls 429.mcf/
mv run/ 429.mcf/
cd 429.mcf/
ls
cd run/
ls
cd ..
vi ../../gen_pin_cmd.py 
ls
mkdir run_base_ref_i386-m32-gcc42-nn.0000
mv run/* run_base_ref_i386-m32-gcc42-nn.0000/
ls
mv run_base_ref_i386-m32-gcc42-nn.0000/ run
cd run/
ls
cd run_base_ref_i386-m32-gcc42-nn.0000/
cd .././..
cd ..
ls
cd ..
ls
cd memtrace/
ls
vi script.sh 
make PIN_ROOT=/home/lgao027/pin
apt install make
sudo apt install make
gcc
sudo apt install gcc
sudo apt update
sudo apt install gcc
sudo apt install build-essential
gcc -v
sudo apt install gcc-multilib g++-multilib
make PIN_ROOT=/home/lgao027/pin
ls
rm -r obj-intel64/
cd ..
ls
cd pin/
ls
cd source/
ls
cd tools/
ls
cd Config/
ls
vi unix.vars 
cd ../../..
cd ../memtrace/
ls
make PIN_ROOT=/home/lgao027/pin
ls
ls obj-ia32/
chmod +x script.sh 
./script.sh 
ls /home/lgao027/memtrace/output_gcc9/pin_mcf_runspec_amd_1
ls /home/lgao027/memtrace/output_gcc9/
cat /home/lgao027/memtrace/output_gcc9/pin_output_mcf.log 
ls -l /home/lgao027/CPU2006/429.mcf/run/run_base_ref_i386-m32-gcc42-nn.0000/mcf_base.i386-m32-gcc42-nn
chmod +x /home/lgao027/CPU2006/429.mcf/run/run_base_ref_i386-m32-gcc42-nn.0000/mcf_base.i386-m32-gcc42-nn
ls /home/lgao027/CPU2006/429.mcf/run/run_base_ref_i386-m32-gcc42-nn.0000/inp.in
/home/lgao027/pin/pin -t /home/lgao027/memtrace/obj-ia32/memtrace.so -o /home/lgao027/memtrace/output_gcc9/pin_mcf_runspec_amd_1 -- /home/lgao027/CPU2006/429.mcf/run/run_base_ref_i386-m32-gcc42-nn.0000/mcf_base.i386-m32-gcc42-nn /home/lgao027/CPU2006/429.mcf/run/run_base_ref_i386-m32-gcc42-nn.0000/inp.in
ls
ls -l
cd ..
ls -l
cd memtrace/
ls
vi memtrace.cpp 
nohup ./script.sh &
ls
vi nohup.out 
ps -aux | grep pin
ls
ls -l memtrace.log 
ps -aux | grep pin
ls
sudo apt install golang-go
go init
go mod
ls
cd cmd
ls
cd dump/
ls
go build
echo $GOROOT
echo $GOPATH
go env
export GOPATH=/home/lgao027/go
export GOROOT=/usr/lib/go-1.13
go build
cd ..
ls
cd ..
ls
go init
go --help
go mod init
go mod init github.com/aclements/memtrace
ls
cd cmd/dump/
go build
ls
cd ../..
ls
ps -aux | grep pin
ls
ls -l memtrace.log 
htop
cd ..
ls
vi .bash_history 
cd memtrace/
ls -l memtrace.log 
htop
cd ..
ls
vi .bash_history 
ps -aux | grep pin
vi .bash_history 
echo $HISTCONTROL
vi .bashrc 
cd memtrace/
ps -aux | grep pin
ls -l memtrace.log 
ls
cd memtrace/
ls
ls -l memtrace.log 
htop
ls
cd memtrace/
ls
ls -l memtrace.log 
ps -aux | grep mcf
chmod +x script.sh
mkdir -p CPU2006/429.mcf/run/run_base_ref_i386-m32-gcc42-nn.0000
