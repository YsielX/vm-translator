from GeneralVM import GeneralVM
import argparse

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config')
    parser.add_argument('--bin')
    args = parser.parse_args()

    codes=open(parser.bin,'rb').read()

    vm=GeneralVM(parser.config)
    open('output','wb').write(vm.to_x64(codes))