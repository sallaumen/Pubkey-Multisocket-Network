#!/usr/bin/python3
# Author: Lucas C. Tavano
# Date: 13/01/2018

import subprocess
from menu import Menu


def syscall(p_command):
    v_subProcess = subprocess.run(p_command, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    return v_subProcess.stdout.decode('utf-8').split('\n')[:-1]


# -----------------Global config---------------------
print("--------- Bem vindo ao Multicast. ---------")

# ip = input("Escolha o ip para trabalhar:" )
# porta = input("Escolha a porta para trabalhar:" )

ip = '230.177.177.177'
porta = 6789

# Read shared key from file

try:
    personal_id = syscall("""ifconfig | grep ether | head -1 | awk {'print $2'}""")[0]  # wlan_name
except:
    print("EXCEPT")
    personal_id = syscall("""ifconfig | grep HWaddr | head -1 | awk {'print $5'}""")[0]  # wlan_name

personal_id = personal_id.replace(':', "")
try:
    print("Meu ID é {0}".format(personal_id))
    my_pubkey_file_name = "id_rsa.pub"
    my_privkey_file_name = "id_rsa"
    key = syscall("cat ./my_keys/{0}".format(my_pubkey_file_name))[0]
    priv_key = syscall("cat ./my_keys/{0}".format(my_privkey_file_name))[0]
    print("Meu public key é {0}".format(key))
except Exception as exc:
    print("Erro: {0}".format(exc))
    exit()

print("------------------------------------------")


# --------------------------------------------------

# ---------Atualiza horarios----------
# print("Atualizando horarios\n")
# syscall("ntpdate -s pool.ntp.br")
# -----------------------------------


if __name__ == '__main__':
    Menu(syscall, ip, porta, personal_id, key)

    exit()
