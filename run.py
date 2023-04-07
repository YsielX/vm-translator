from GeneralVM import GeneralVM
import argparse

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config')
    parser.add_argument('--bin')
    args = parser.parse_args()

    codes=open(args.bin,'rb').read()

    vm=GeneralVM(args.config)
    open('./test/output','wb').write(vm.to_x64(codes))