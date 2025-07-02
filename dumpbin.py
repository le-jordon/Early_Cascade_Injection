def format_as_c_array(name,  data_chunks):
    lines = [f"BYTE {name}[] ="]
    for chunk in data_chunks:
        line = " " * 20 + "\"" + "".join(f"\\x{b:02x}" for b in chunk) + "\""
        lines.append(line)
    lines.append(";\n")
    return "\n".join(lines)

def dump_bin_as_c_arrays(stager, output_path):
    with open(stager, "rb") as f:
        data = f.read()

    # Split into 16-byte chunks
    chunks = [data[i:i+16] for i in range(0, len(data), 16)]
    # with open(shellcode, "rb") as f:
    #     data2 = f.read()

    # Split into 16-byte chunks
    # shellcode_chunks = [data2[i:i+16] for i in range(0, len(data2), 16)]

    # with open(output_path, "w") as out:
    #     out.write("// Auto-generated shellcode header\n\n")
    #     out.write("#include <Windows.h>\n\n")
    #     out.write(format_as_c_array("x64_stub", chunks))
    #     out.write("\n")
    #     out.write(format_as_c_array("x64_shellcode", shellcode_chunks))

# Usage
dump_bin_as_c_arrays("stager.bin", "x64_shellcode_output.h")
