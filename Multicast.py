#!/usr/bin/python3
#Author: Lucas C. Tavano
#Date: 13/01/2018import socket
import struct
import sys
import threading
import subprocess
import os
import time
from urllib.parse import urlencode
import socket
import json
from datetime import datetime
from urllib.parse import unquote
from Crypto.Cipher import PKCS1_OAEP #pip3 install Crypto
from Crypto.PublicKey import RSA
import pickle

def syscall(p_command):
    v_subProcess = subprocess.run(p_command, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    return v_subProcess.stdout.decode('utf-8').split('\n')[:-1]

#-----------------Global config---------------------
print("--------- Bem vindo ao Multicast. ---------")
#ip = input("Escolha o ip para trabalhar:" )
#porta = input("Escolha a porta para trabalhar:" )
ip = '230.177.177.177'
porta = 6789
# Read shared key from file
try:
    personal_id = syscall("""ifconfig | grep ether | head -1 | awk {'print $2'}""")[0]  # wlan_name
except:
    print("EXCEPT")
    personal_id = syscall("""ifconfig | grep HWaddr | head -1 | awk {'print $5'}""")[0]  # wlan_name

personal_id = personal_id.replace(':',"")
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
#--------------------------------------------------

#---------Atualiza horarios----------
#print("Atualizando horarios\n")
#syscall("ntpdate -s pool.ntp.br")
#-----------------------------------

class crypto():
    @staticmethod
    def encrypt_RSA(public_key_loc, message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''

        key = open(public_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message.encode()) #[1:]
        #encrypted = encrypted.decode("utf-8")#.replace("'", '"')
        #print ("minha chave é: {0}".format([str(encrypted)]))
        #return str(encrypted)[2:-1]
        return (encrypted) #.decode('utf8')

    @staticmethod
    def decrypt_RSA(private_key_loc, encrypted_message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''

        key = open(private_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.decrypt(encrypted_message)

        return str(encrypted)

def multicastSender():
    '''
    função crua que envia a chave publica para a rede administrada na funcao multicastReceiver
    '''
    multicast_group = (str(ip), int(porta))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set a timeout so the socket does not block
    # indefinitely when trying to receive data.
    sock.settimeout(2)
    # Set the time-to-live for messages to 1 so they do not
    # go past the local network segment.
    ttl = struct.pack('b', 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    try: # Look for responses from all recipients
        #while True:
        print("\n\n-----KEY SENDED-----")
        #JSON com o id da maquina que é seu MAC e sus public_key
        message = {'id': personal_id, 'key': key, 'time':datetime.now().strftime("%H:%M:%S"), 'type': 'key'}
        # Send data to the multicast group
        print('sending {0}'.format(message))
        sent = sock.sendto(str(message).encode('utf-8'), multicast_group)
        try:
            data, server = sock.recvfrom(16)
            print('Recebido {!r} de {}'.format(data, server))
        except socket.timeout:
            print("Sem respostas - Timeout")
        #break
        #time.sleep(60)
    finally:
        print('Closing socket')
        sock.close()

def multicastMessageSender(message, destiny):
    '''
    mensagem e o dado sem criptografica
    destiny e o mac do destinatario
    '''
    #Criptografa a mensagem e retorna na variavel, ex:
    #destiny_key = syscall("cat ./others_keys/{0}".format(destiny_key_address))[0]
    destiny_key_address = "{0}@{0}.pub".format(destiny)
    message_cryp_dest = crypto.encrypt_RSA("./others_keys/{0}".format(destiny_key_address), message)   #Mensagem criptografada na chave do destinatario
    message_cryp_MINE = crypto.encrypt_RSA("./my_keys/id_rsa.pub", message)                            #Mensagem critpografada na minha própria chave
    message_decripted_MINE = crypto.decrypt_RSA("./my_keys/id_rsa", message_cryp_MINE)                 #Minha mensagem descriptografada
    #message = crypto.encrypt_RSA("./my_keys/b827eb6cfa20@b827eb6cfa20.pub", message)
    print("\n\n--Demosntração do dado pós criptografia na chave pública do destinatario: {0}".format(message_cryp_dest))
    #print("\n\n--Demosntração do dado pós criptografia na MINHA propria chave PÚBLICA: {0}".format(message_cryp_MINE))
    #print("\n\n--Demosntração do dado pós DEScriptografica na MINHA própria chave PRIVADA: {0}".format(message_decripted_MINE))
    multicast_group = (str(ip), int(porta))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set a timeout so the socket does not block
    # indefinitely when trying to receive data.
    sock.settimeout(2)
    # Set the time-to-live for messages to 1 so they do not
    # go past the local network segment.
    ttl = struct.pack('b', 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    try: # Look for responses from all recipients
        while True:
            print("\n\n-----MESSAGE SENDED-----")
            #JSON com o id da maquina que é seu MAC e sus public_key
            print(message)
            message = {'sender_id': personal_id, 'destiny_id': destiny ,'message': message, 'message_encrypted': "AQUI VAI A variavel message_crip_dest", 'time':datetime.now().strftime("%H:%M:%S"), 'type': 'encrypted-message'}
            # Send data to the multicast group
            print('sending {0}'.format(message))
            sent = sock.sendto(str(message).encode('utf-8'), multicast_group)
            try:
                data, server = sock.recvfrom(16)
                print('Recebido {!r} de {}'.format(data, server))
            except socket.timeout:
                print("Sem respostas - Timeout")
            break
    finally:
        print('Closing socket.')
        sock.close()

def multicastArchiveRequest(destiny):
    '''
    destiny é o endereço MAC do destinatario
    '''
    multicast_group = (str(ip), int(porta))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set a timeout so the socket does not block
    # indefinitely when trying to receive data.
    sock.settimeout(2)		#Timeout em segundos
    # Set the time-to-live for messages to 1 so they do not
    # go past the local network segment.
    ttl = struct.pack('b', 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    try: # Look for responses from all recipients
        while True:
            print("\n\n-----MESSAGE SENDED-----")
            #JSON com o id da maquina que é seu MAC e sus public_key
            message = {'sender_id': personal_id, 'destiny_id': destiny ,'message': "Aguardando arquivo", 'time':datetime.now().strftime("%H:%M:%S"), 'type': 'file'}
            # Send data to the multicast group
            print('sending {0}'.format(message))
            sent = sock.sendto(str(message).encode('utf-8'), multicast_group)
            try:
                data, server = sock.recvfrom(16384)
                print('Recebido {!r} de {}'.format(data, server))
            except socket.timeout:
                print("Sem respostas - Timeout")
            break
    finally:
        print('Closing socket.')
        sock.close()

def multicastReceiver():
    multicast_group = ip
    server_address = ('', porta)
    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind to the server address
    sock.bind(server_address)
    # Tell the operating system to add the socket to
    # the multicast group on all interfaces.
    group = socket.inet_aton(multicast_group)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
    # Receive/respond loop
    while True:
        #print('\nAguardando mensagem:')
        no_ack = 0
        data, address = sock.recvfrom(1024)
        print("\n\n-----RECEIVED-----")
        print('Datagram recebido: {0} bytes de {1}'.format(len(data), address))
        #print("  -Message: {0}".format(data))
        print("  -Lenght in bytes: {0}".format(len(data)))
        print("  -From: {0}".format(address))
        if len(data) > 40:
            data = data.decode().replace("'", '"')
            data = json.loads(data)

            #Key processing ---- TERMINADO
            if data["type"] == "key":
                print("Checando se ja tenho esta chave...")
                save = 0
                new_pubkey_file_name = "{0}@{0}.pub".format(data['id'])
                if(new_pubkey_file_name != "{0}@{0}.pub".format(personal_id)):
                    try:
                        flag = syscall("""ls -l ./others_keys | grep {0}""".format(new_pubkey_file_name))[0]
                        print("a flag e: {0}".format(flag))
                        if flag == '':
                            print("Chave não encontrada.")
                            save = 1
                        else:
                            save = 0
                    except Exception as exc: #Caso não tenha a chave,sempre vai cair nessa excessao
                        print("Chave não encontrada.")
                        save = 1

                    if save == 1:
                        print("Salvando em {0}@{1}.pub a chave publica recebida.".format(data['id'], data['id']))
                        syscall("echo {0} > ./others_keys/{1}@{2}.pub".format(data['key'], data['id'], data['id']))
                        print("Realizando broadcast de minha chave.")
                        multicastSender()
                    else:
                        print("Chave pública ja existente. Ignorando.")
                else:
                    print("Recebida minha própria chave, ignorando...")

            #Message receiver ---- FALTA A CRIPTOGRAFIA NO JSON
            if data["type"] == "encrypted-message":
                if data["destiny_id"] == personal_id: #Checa se a mensagem é para mim
                    print("Datagram Received!")
                    print("  -Mensagem enviada de {0}".format(data["sender_id"]))
                    print("  -Mensagem enviada para {0}".format(data["destiny_id"]))
                    print("  -Mensagem mensagem: {0}".format(data["message"]))
                    #print("  -Mensagem criptografada: {0}".format(data["message_encrypted"]))
                    #print("  -Mensagem descriptografada: {0}".format(crypto.decrypt_RSA.data["message_encrypted"]))

            #File Receiver ---- FALTA TODA IMPLEMENTAÇÃO DAS FILAS E CONTROLE DE ARQUIVOS
            if data["type"] == "file":
                if data["destiny_id"] == personal_id: #Checa se a mensagem é para mim
                    print("Solicitação de arquivo recebida!")
                    if syscall("cat ./arquivos/lock")[0] == '1':
                        print("Arquivo em lock, acesso negado")
                        sock.sendto(b'ACESSO NEGADO - ARQUIVO BLOQUEADO', address)
                        no_ack = 1
                    print("Dando Lock em arquivo.")
                    syscall("echo 1 > ./arquivos/lock")				#Todo o lock de dados tem que ser refeito em objetos e nao em arquivos
                    file_data = syscall("cat ./arquivos/meu_arquivo")[0]
                    print("Responendo dado do arquivo: {0}".format(file_data))
                    sock.sendto(file_data.encode(), address)
                    no_ack = 1
                    time.sleep(4)
                    print("Removendo Lock de arquivo.")
                    syscall("echo 0 > ./arquivos/lock")
        if no_ack == 0:
            sock.sendto(b'ack', address)

def menu():
    menu_var = input("\n    -[1] Escutar e enviar dados\n    -[2] Para enviar menssagem\n    -[3] Para enviar arquivo\n    -[Qualquer outra tecla conhecida pelo homem] Para finalizar o programa\n    : ")
    if menu_var == "1":
        clean_keys = input("    -Deseja apagar as keys atuais? (Y/N) ")
        if clean_keys == "Y":
            print("     Limpando keys atuais")
            syscall("rm ./others_keys/*")
        thread_receive = threading.Thread(target=multicastReceiver, args=())
        thread_receive.start()
        thread_sender = threading.Thread(target=multicastSender, args=())
        thread_sender.start()
        return menu()

    elif menu_var == "2":
        print("\n    |--As opções de destinatários são: ")
        for i in syscall("ls -l ./others_keys/ | grep .pub"):
            i = i.split(" ")[8].split("@")[0]
            print("    |---> {0}".format(i))
        destino_valido = 0
        while(destino_valido == 0):
            destiny = input("    |---Coloque o nome do destino: ")
            destiny_key_address = "{0}@{0}.pub".format(destiny)
            try:
                destiny_key = syscall("cat ./others_keys/{0}".format(destiny_key_address))[0]
                destino_valido = 1
            except:
                print("    |---X Destino inválido, chave não encontrada")
                destino_valido = 0
        message = input("    |---Coloque a mensagem que deseja enviar: ")
        multicastMessageSender(message, destiny)
        return menu()

    elif menu_var == "3":
        print("\n    |--As opções de destinatários são: ")
        for i in syscall("ls -l ./others_keys/ | grep .pub"):
            i = i.split(" ")[8].split("@")[0]
            print("    |---> {0}".format(i))
        destino_valido = 0
        while(destino_valido == 0):
            destiny = input("    |---Coloque o nome do destino: ")
            destiny_key_address = "{0}@{0}.pub".format(destiny)
            try:
                destiny_key = syscall("cat ./others_keys/{0}".format(destiny_key_address))[0]
                destino_valido = 1
            except:
                print("    |---X Destino inválido, chave não encontrada")
                destino_valido = 0
        multicastArchiveRequest(destiny)
        return menu()
    else:
        exit()


if __name__ == '__main__':
    menu()

    exit()
