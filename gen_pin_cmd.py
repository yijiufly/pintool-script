import os
import sys
import subprocess
import argparse

# Define global variables to store the root paths of SPEC and PIN
SPEC_ROOT_PATH = "/root/CPU2006"
PIN_ROOT_PATH = "/root/gcloud/pin"
#PIN_TOOL_DIR_NAME = PIN_ROOT_PATH + "/source/tools/" + "MyPinToolMemAccess"
#SO_FILE = "ToolMemAccess.so"
PIN_TOOL_DIR_NAME = "/root/gcloud/callgraph"
SO_FILE = "calladdr.so"
PIN_PATH = PIN_ROOT_PATH + "/pin"
# num = 1

def generate_pin_command(name, extra_args=""):
    # global num
    num = 1

    # Print the name that is currently being processed
    print(f"Processing: {name}")

    shortname = name.split('.')[1]

    run_directory = f"{SPEC_ROOT_PATH}/{name}/run/run_base_ref_i386-m32-gcc42-nn.0000/"
    file_path = os.path.join(run_directory, "speccmds.cmd")
    output_directory = f"{PIN_TOOL_DIR_NAME}/output_gcc9"

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    old_files = os.listdir(output_directory)
    for old_file in old_files:
        if old_file.startswith(f"pin_{shortname}_runspec_amd_") and old_file.endswith('.csv'):
            os.remove(os.path.join(output_directory, old_file))
        if old_file == f"pin_output_{shortname}.log":
            os.remove(os.path.join(output_directory, old_file))

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

            for line in lines:
                if "-o" in line:
                    components = line.split("../")
                    exe_name = components[1].split()[0].split("/")[-1]

                    remaining_args = components[1].split()[1:]

                    actual_args = []
                    for arg in remaining_args:
                        if os.path.isfile(os.path.join(run_directory, arg)):
                            actual_args.append(os.path.join(run_directory, arg))
                        else:
                            actual_args.append(arg)

                    actual_command = " ".join(actual_args)
                    if shortname == "milc":
                        actual_command += f" {extra_args}"

                    pin_command = f"{PIN_PATH} -t {PIN_TOOL_DIR_NAME}/obj-ia32/{SO_FILE} -o {output_directory}/pin_{shortname}_runspec_amd.csv -- {SPEC_ROOT_PATH}/{name}/run/run_base_ref_i386-m32-gcc42-nn.0000/{exe_name} {actual_command}"

                    # Print the generated pin_command
                    print(pin_command)

                    with open(os.path.join(output_directory, f"pin_output_{shortname}.log"), "a") as log_file:
                        process = subprocess.Popen(pin_command, shell=True, stdout=log_file, stderr=log_file, cwd=run_directory)
                        process.wait()
                        log_file.write("\n")

                    num += 1
                    break

    except FileNotFoundError:
        print(f"The file '{file_path}' does not exist.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Pin Command Script")
    parser.add_argument("names", nargs="+", help="Names in the format <number.benchmarkName>")
    parser.add_argument("--extra-args", default="", help="Extra arguments to be added based on specific conditions")
    args = parser.parse_args()

    for name in args.names:
        generate_pin_command(name, args.extra_args)
