#!/usr/bin/env python3

import os, sys
import json
import re
import jsonpath
import subprocess

rootPath = '/home/renardbebe/Desktop/Tools/fuzzers/sFuzz-students/build/fuzzer/'
resultPath = rootPath + 'contracts/'


if __name__ == '__main__':
    datasetList = ['Etherscan', 'SolidiFI', 'SWC']

    # for each dataset
    for d in datasetList :
        datasetPath = resultPath + d + '/'
        if not os.path.exists(datasetPath) :
            continue

        file_lists = os.listdir(datasetPath)
        for contractFolder in file_lists :
            if os.path.isdir(os.path.join(datasetPath, contractFolder)) :
                contractName = contractFolder[:contractFolder.index(".sol")]

                if not os.path.exists(datasetPath + contractFolder + '/outputs.txt') :
                    print(contractFolder + " Failed")
                    continue

                mapping = {}  # dict
                cmd = "solc --hashes " + datasetPath + contractName + ".sol > " + datasetPath + contractFolder + "/signature"
                ret = subprocess.call(cmd, shell=True)
                if ret == 1 :
                    print("Extract hashes error.")
                with open(datasetPath + '/' + contractFolder + '/signature', 'r', encoding='utf8') as f:
                    lines = f.readlines()
                    for line in lines :
                        line = line.strip('\n')
                        if line[8:10] == ": " :
                            sig = line[:line.index(":")]
                            funcName = line[line.index(":")+2:]
                            mapping[sig] = funcName
                    f.close()
                # print(mapping)

                results = []
                with open(datasetPath + contractFolder + '/outputs.txt', 'r', encoding='utf8') as fr:
                    results = fr.readlines()
                    fr.close()
                
                with open(datasetPath + '/' + contractFolder + '/outputs.txt', 'w+', encoding='utf8') as fp:
                    for line in results :
                        content = line.strip('\n')
                        if '*' not in content :
                            signature = content.replace("0x", "")
                            if signature in mapping :
                                funcName = mapping[signature]
                                fp.write(funcName + "\n")
                            else :
                                fp.write(signature + "\n")
                        else :
                            fp.write(content + "\n")
                    fp.close()