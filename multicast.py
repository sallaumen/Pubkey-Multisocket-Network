import subprocess
from menu import Menu
#from receiver import Receiver
#from sender import Sender

def syscall(p_command):
    v_subProcess = subprocess.run(p_command, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    return v_subProcess.stdout.decode('utf-8').split('\n')[:-1]


# -----------------Global config---------------------
print("--------- Bem vindo ao Multicast. ---------")

ip = '230.177.177.177'
porta = 6789
# ip = input("Escolha o ip para trabalhar:" )
# porta = input("Escolha a porta para trabalhar:" )

# ---------Atualiza horarios----------
# print("Atualizando horarios\n")
# syscall("ntpdate -s pool.ntp.br")
# -----------------------------------

    
if __name__ == '__main__':
    Menu(ip, porta)
    exit()
