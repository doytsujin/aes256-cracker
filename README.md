# Making changes
If you want to modify this repo, delete `main.cu` and replace it with a symlink to `main.c`, i.e.

```
$ git clone https://github.com/jkarns275/aes256-cracker
$ cd aes256-cracker/
$ rm -rf main.cu
$ ln main.c main.cu
$ diff main.c main.cu

```
