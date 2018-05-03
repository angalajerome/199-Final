import json
import sys

def getopts(argv):
    opts = {}  # Empty dictionary to store key-value pairs.
    while argv:  # While there are arguments left to parse...
        if argv[0][0] == '-':  # Found a "-name value" pair.
            opts[argv[0]] = argv[1]  # Add key and value to the dictionary.
        argv = argv[1:]  # Reduce the argument list by copying it starting from index 1.
    return opts

if __name__ == '__main__':
    from sys import argv
    myargs = getopts(argv)
    new_dir = str(myargs['-dir'])
    with open('scripts/json_files/running_test_data_base.json','r') as original_file:
        original = original_file.readlines()

    new_thing = []
    for line in original:
        if "[DIR]" in line:
            start_index = line.find('[')
            end_index = line.find(']')+1
            new_line = line[:start_index]+new_dir+line[end_index:]
            new_thing.append(new_line)
        else:
            new_thing.append(line)

    with open('scripts/json_files/running_test_data.json','w') as new_file:
        write_final=""
        for line in new_thing:
            write_final = write_final + line
        new_file.write(write_final)


