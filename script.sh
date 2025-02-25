PIN_HOME=/root/gcloud/pin
HOME=/root/gcloud/memtrace
cd $HOME
# make PIN_ROOT=$PIN_HOME
# mkdir $HOME/output_gcc9
# echo bzip2
# python3 -u $HOME/memtrace/memtrace.py bzip2
# echo lbm
# python3 -u $HOME/memtrace/memtrace.py lbm
# $PIN_HOME/pin -t $HOME/obj-ia32/memtrace.so -o $HOME/output_gcc9/pin_milc_runspec_amd_1 -- /home/researcher/Downloads/Lian/CPU2006/433.milc/run/run_base_ref_i386-m32-gcc42-nn.0000/milc_base.i386-m32-gcc42-nn < /home/researcher/Downloads/Lian/CPU2006/433.milc/run/run_base_ref_i386-m32-gcc42-nn.0000/su3imp.in
# ./cmd/dump/dump memtrace.log > output_gcc9/memaccess_433.milc.csv

# $PIN_HOME/pin -t $HOME/obj-ia32/memtrace.so -o lbm -- /root/CPU2006/470.lbm/run/run_base_ref_i386-m32-gcc42-nn.0000/lbm_base.i386-m32-gcc42-nn 3000 reference.dat 0 0 /root/CPU2006/470.lbm/run/run_base_ref_i386-m32-gcc42-nn.0000/100_100_130_ldc.of
# python3 -u $HOME/memtrace/memtrace.py lbm

for bin in 400.perlbench # 464.h264ref 400.perlbench #401.bzip2  #429.mcf  401.bzip2 456.hmmer 464.h264ref 462.libquantum
do
    echo $bin
    python3 /root/gcloud/gen_pin_cmd.py $bin
    shortname=${bin:4}
    # python3 -u $HOME/memtrace/memtrace.py $shortname
done
