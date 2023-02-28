import subprocess
import os

GHIDRA_ANALYZEHEADLESS_PATH = 'path/To/Ghidra/support/analyzeHeadless'
BINARY_PATH = 'path/to/bins'

def ghidra(binary):
    if not os.path.exists(f"./src/tmp"):        
        os.mkdir(f"./src/tmp")
    cmd = []
    
    if not os.path.exists(binary):
        print("[-] input path does not exist")
        return

    cmd = [
        GHIDRA_ANALYZEHEADLESS_PATH,
        f"ghidra{os.sep}tmp",
        "analyze",
        "-prescript",
        "src/pre.py",
        "-postscript",
        "src/post.py",
        "-import",
        binary,
    ]   
    subprocess.run(cmd)
    return


if __name__ == '__main__':       
    binaries = os.listdir(BINARY_PATH)    
    for binary in binaries:                        
        binary = BINARY_PATH + binary        
        ghidra(binary)
            
    

    


