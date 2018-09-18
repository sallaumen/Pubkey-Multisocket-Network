import base64
import json
import socket
import struct
import threading
import random
from datetime import datetime
import subprocess
from crypto import crypto

def syscall(p_command):
    v_subProcess = subprocess.run(p_command, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    return v_subProcess.stdout.decode('utf-8').split('\n')[:-1]

ip = '230.177.177.177'
porta = 6789

try:
    personal_id = syscall("""ifconfig | grep ether | head -1 | awk {'print $2'}""")[0]  # wlan_name
except:
    try:
        print("EXCEPT")
        personal_id = syscall("""ifconfig | grep HWaddr | head -1 | awk {'print $5'}""")[0]  # wlan_name
    except:
        personal_id = syscall("""ifconfig | grep ether | head -1 | awk {'print $2'}""")[0]  # wlan_name

personal_id = personal_id.replace(':', "")
rander = random.randint(0,5000)
personal_id = personal_id+str(rander)
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



class states():
    RELEASED = "RELEASED"
    WANTED = "WANTED"
    HELD = "HELD"
    arq_state = [RELEASED,RELEASED]
    state_owners = ["none","none"]
    fila1_wanted = []
    fila2_wanted = []

states_obj = states()

class Sender():
    @staticmethod
    def multicastFileStateCaster():
        '''
        mensagem e o dado sem criptografica
        destiny e o mac do destinatario
        #'''
        message = "Mudanca de state"

        # Mensagem critpografada na minha própria chave
        digital_signed_message, digest = crypto.encrypt_RSA("./my_keys/id_rsa", message)

        print("\n\n--Demonstração do dado enviado com assinatura digital: {0}".format(digest))

        multicast_group = (str(ip), int(porta))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        try:  # Look for responses from all recipients
            print("\n\n-----PEDIDO DE DADO REALIZADO-----")
            print(message)
            message = {'message': message,
                       'message_encrypted': digital_signed_message,
                       'states': states_obj.arq_state,
                       'states_owners': states_obj.state_owners,
                       'digest': base64.encodestring(digest).decode(),
                       'fila1': states_obj.fila1_wanted,
                       'fila2': states_obj.fila2_wanted,
                       'time': datetime.now().strftime("%H:%M:%S"),
                       'sender_id': personal_id,
                       'type': 'file_update'}

            json_string = json.dumps(message)

            json_bytes = json_string.encode('utf-8')

            sent = sock.sendto(json_bytes, multicast_group)

        finally:
            sock.close()

    @staticmethod
    def multicastSender(ip, porta, personal_id, key):
        '''
        função crua que envia a chave publica para a rede administrada na funcao multicastReceiver
        '''
        multicast_group = (str(ip), int(porta))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        try:  # Look for responses from all recipients
            print("\n\n-----KEY SENDED-----")
            message = {'id': personal_id,
                       'key': key,
                       'time': datetime.now().strftime("%H:%M:%S"),
                       'type': 'key'}

            print('sending {0}'.format(message))

            json_string = json.dumps(message)

            json_bytes = json_string.encode('utf-8')

            sent = sock.sendto(json_bytes, multicast_group)

        finally:
            print('Closing socket')
            sock.close()


def printFilas():
    #Mostrando fila 1
    counter=0
    print("\nFila do processo 1: ")
    for i in states_obj.fila1_wanted:
        counter +=1
        print("[{0}] {1}".format(counter, states_obj.fila1_wanted[counter-1]))

    #Mostrando fila 2
    counter=0
    print("\nFila do processo 2: ")
    for i in states_obj.fila2_wanted:
        counter +=1
        print("[{0}] {1}".format(counter, states_obj.fila2_wanted[counter-1]))

def administra_dados(data_num):
    # checa se o dado esta released
    if states_obj.arq_state[data_num] == states_obj.RELEASED:
        states_obj.arq_state[data_num] = states_obj.HELD
        states_obj.state_owners[data_num] = str(personal_id)
        Sender.multicastFileStateCaster()
        return "        ===== O dado é seu!"

    elif data_num == 0:
        # se nao, edita a fila e se insere no fim
        if states_obj.arq_state[data_num] == states_obj.HELD:
            states_obj.fila1_wanted = states_obj.fila1_wanted + [personal_id]
            printFilas()
            Sender.multicastFileStateCaster()
            return "        ===== Adicionado à fila"

    elif data_num == 1:
        # se nao, edita a fila e se insere no fim
        if states_obj.arq_state[data_num] == states_obj.HELD:
            states_obj.fila2_wanted = states_obj.fila2_wanted + [personal_id]
            printFilas()
            Sender.multicastFileStateCaster()
            return "        ===== Adicionado à fila"


class Menu():
    def __init__(self, ip, porta,):
        self.porta = porta
        self.ip = ip
        self.menu()

    def menu(self):
        menu_var = input(
            "\n    -[1] Escutar e enviar dados"
            "\n    -[2] Solicitar arquivo"
            "\n    -[3] Liberar arquivo"
            "\n    -[Outras teclas] Finalizar o programa\n    : ")

        if menu_var == "1":
            clean_keys = "Y" #input("    -Deseja apagar as keys atuais? (Y/N) ")
            if clean_keys == "Y":
                print("     Limpando keys atuais")
                syscall("rm ./others_keys/*")
            thread_receive = threading.Thread(target=Receiver.multicastReceiver, args=(self.ip,
                                                                                       self.porta,
                                                                                       personal_id,
                                                                                       key))
            thread_receive.start()
            thread_sender = threading.Thread(target=Sender.multicastSender,
                                             args=(self.ip, self.porta, personal_id, key))
            thread_sender.start()
            return self.menu()

        elif menu_var == "2":
            destino_valido = 0
            print("\n    |--A fila os dados atuais são: 1- {0}, 2- {1}".format(states_obj.arq_state[0], states_obj.arq_state[1]))
            while (destino_valido == 0):
                data_num = int(input("        |---Coloque o o numero do dado desejado: "))
                try:
                    if data_num == 1 or data_num == 2:
                        destino_valido = 1
                        data_num -= 1
                        ret = administra_dados(data_num)
                        print(ret)
                    else:
                        print("    |---X Número invalido")
                        destino_valido = 0
                except Exception as exc:
                    print (exc)
            return self.menu()

        #IMPLEMENTAR
        elif menu_var == "3":
            destino_valido = 0
            print("\n    |--A fila os dados atuais são: 1- {0}, 2- {1}".format(states_obj.arq_state[0], states_obj.arq_state[1]))
            j=0
            destino_valido = 1
            for i in states_obj.state_owners:
                j+=1
                if i == personal_id:
                    print("       Você é dono do dado {0}".format(j))
                    destino_valido = 0
            if destino_valido == 1:
                print("      Você não é dono de nenhum dado!")
            while (destino_valido == 0):
                data_num = int(input("        |---Selecione o dado que deseja liberar: "))
                try:
                    if data_num == 1 or data_num == 2:
                        if states_obj.state_owners[data_num-1] == personal_id:
                            destino_valido = 1
                            states_obj.arq_state[data_num-1] = states_obj.RELEASED
                            states_obj.state_owners[data_num-1] = "none"
                            Sender.multicastFileStateCaster()
                            print("      Objeto {0} liberado com sucesso".format(data_num))
                    else:
                        print("    |---X Número invalido")
                        destino_valido = 0
                except Exception as exc:
                    print (exc)
            return self.menu()

        else:
            exit()


class Receiver():
    @staticmethod
    def multicastReceiver(ip, porta, personal_id, key):
        multicast_group = ip
        server_address = ('', porta)
        # Create the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to the server address
        sock.bind(server_address)
        # Tell the operating system to add the socket to
        # the multicast group on all interfaces.
        group = socket.inet_aton(multicast_group)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Receive/respond loop
        while True:
            data, address = sock.recvfrom(16384)
            print("\n\n-----RECEIVED-----")
            print('Datagram recebido: {0} bytes de {1}'.format(len(data), address))
            # print("  -Message: {0}".format(data))
            print("  -Lenght in bytes: {0}".format(len(data)))
            print("  -From: {0}".format(address))
            if len(data) > 40:
                data2 = data

                data = data.decode()
                data = json.loads(data)

                # File Receiver
                if data["type"] == "file_update":
                    try:
                        states_obj.arq_state = data["states"]
                        states_obj.state_owners = data["states_owners"]
                        states_obj.fila1_wanted = data["fila1"]
                        states_obj.fila2_wanted = data["fila2"]

                        if len(states_obj.fila1_wanted) > 0:
                            if states_obj.fila1_wanted[0] == personal_id and states_obj.arq_state[
                                0] == states_obj.RELEASED:
                                states_obj.arq_state[0] = states_obj.HELD
                                states_obj.fila1_wanted = states_obj.fila1_wanted[1:]
                                states_obj.state_owners[0] = str(personal_id)
                                printFilas()
                                Sender.multicastFileStateCaster()
                        if len(states_obj.fila2_wanted) > 0:
                            if states_obj.fila2_wanted[0] == personal_id and states_obj.arq_state[
                                1] == states_obj.RELEASED:
                                states_obj.arq_state[1] = states_obj.HELD
                                states_obj.fila2_wanted = states_obj.fila2_wanted[1:]
                                states_obj.state_owners[1] = str(personal_id)
                                printFilas()
                                Sender.multicastFileStateCaster()

                        # Show digital signature
                        print("Datagram Received!")
                        print("  -Mensagem enviada de {0}".format(data["sender_id"]))
                        print("  -Mensagem mensagem: {0}".format(data["message"]))

                        # public_key = syscall("cat ./others_keys/{0}@{0}.pub".format(data["sender_id"]))

                        public_key_path = "./others_keys/{0}@{0}.pub".format(data["sender_id"])

                        rsa, verified = crypto.decrypt_RSA(public_key_path,
                                                   data["message_encrypted"],
                                                   data['digest'],
                                                   data['message'])

                        print("  -Assinatura digital: {0}".format(rsa))

                    except Exception as exc:
                        print("------------EXCEPTION: {0}".format(exc))

                # Key processing
                if data["type"] == "key":
                    print("Checando se ja tenho esta chave...")
                    save = 0
                    new_pubkey_file_name = "{0}@{0}.pub".format(data['id'])
                    if (new_pubkey_file_name != "{0}@{0}.pub".format(personal_id)):
                        try:
                            flag = syscall("""ls -l ./others_keys | grep {0}""".format(new_pubkey_file_name))[0]
                            print("a flag e: {0}".format(flag))
                            if flag == '':
                                print("Chave não encontrada.")
                                save = 1
                            else:
                                save = 0
                        except Exception as exc:  # Caso não tenha a chave,sempre vai cair nessa excessao
                            print("Chave não encontrada.")
                            save = 1

                        if save == 1:
                            print(
                                "Salvando em {0}@{1}.pub a chave publica recebida.".format(data['id'], data['id']))
                            syscall(
                                "echo {0} > ./others_keys/{1}@{2}.pub".format(data['key'], data['id'], data['id']))
                            print("Realizando broadcast de minha chave.")
                            Sender.multicastFileStateCaster()
                            Sender.multicastSender(ip, porta, personal_id, key)
                            # states.arq_state
                        else:
                            print("Chave pública ja existente. Ignorando.")
                    else:
                        print("Recebida minha própria chave, ignorando...")


