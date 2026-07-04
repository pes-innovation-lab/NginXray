# NginXray
 
Kernel-Level Edge Defense and Plaintext L7 Observability: An eBPF-Based Security Agent for Nginx with Go Integration
 
Mentors: Prachi Jha, Murali Krishna Rao
Interns: Uttam K R, Sarah Kazi, Rehaan Jose Mathew
 
(temporary)
 
## Dependencies
 
### Arch Linux
 
```bash
sudo pacman -S go clang bpftool make
```
 
### Ubuntu
 
```bash
sudo apt update
sudo apt install golang clang bpftool make
```
 
## Usage
 
First time on a fresh clone, run setup once (generates `bpf/vmlinux.h` from your kernel and tidies Go deps):
 
```bash
make setup
```
 
Then build:
 
```bash
make build
```
 
Then run a component as root (build first, the run targets do not build for you):
 
```bash
make run-filter
make run-sniffer
```
 
For all available targets:
 
```bash
make help
```