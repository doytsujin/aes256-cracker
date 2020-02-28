# Running
To run this:
```
mkdir build
cd build
cmake ..
make
```

Then you can run `build/aescracker_mp` for the parallel version,
or `build/aescracker_seq` for the sequential version.

You can compile and run a cuda version if you modify the CMakeLists.txt in the projects root directory,
the binary is named `build/aescracker_cuda`.

# Making changes
If you want to modify this repo, delete `main.cu` and replace it with a symlink to `main.c`, i.e.

```
$ git clone https://github.com/jkarns275/aes256-cracker
$ cd aes256-cracker/
$ rm -rf main.cu
$ ln main.c main.cu
$ diff main.c main.cu

```
