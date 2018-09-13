import json
import socket
import struct
import time
from datetime import datetime


class Receiver():
    @staticmethod
    def multicastArchiveRequest(destiny, ip, porta, personal_id, key):
        '''
        destiny é o endereço MAC do destinatario
        '''
        multicast_group = (str(ip), int(porta))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set a timeout so the socket does not block
        # indefinitely when trying to receive data.
        sock.settimeout(2)  # Timeout em segundos
        # Set the time-to-live for messages to 1 so they do not
        # go past the local network segment.
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        try:  # Look for responses from all recipients
            while True:
                print("\n\n-----MESSAGE SENDED-----")
                # JSON com o id da maquina que é seu MAC e sus public_key
                message = {'sender_id': personal_id, 'destiny_id': destiny, 'message': "Aguardando arquivo",
                           'time': datetime.now().strftime("%H:%M:%S"), 'type': 'file'}
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

    @staticmethod
    def multicastReceiver(ip, porta, personal_id):
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
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Receive/respond loop
        while True:
            no_ack = 0
            data, address = sock.recvfrom(1024)
            print("\n\n-----RECEIVED-----")
            print('Datagram recebido: {0} bytes de {1}'.format(len(data), address))
            # print("  -Message: {0}".format(data))
            print("  -Lenght in bytes: {0}".format(len(data)))
            print("  -From: {0}".format(address))
            if len(data) > 40:
                data = data.decode().replace("'", '"')
                data = json.loads(data)

                # Key processing ---- TERMINADO
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
                            print("Salvando em {0}@{1}.pub a chave publica recebida.".format(data['id'], data['id']))
                            syscall("echo {0} > ./others_keys/{1}@{2}.pub".format(data['key'], data['id'], data['id']))
                            print("Realizando broadcast de minha chave.")
                            multicastSender()
                        else:
                            print("Chave pública ja existente. Ignorando.")
                    else:
                        print("Recebida minha própria chave, ignorando...")

                # Message receiver
                if data["type"] == "encrypted-message":
                    if data["destiny_id"] == personal_id:  # Checa se a mensagem é para mim
                        print("Datagram Received!")
                        print("  -Mensagem enviada de {0}".format(data["sender_id"]))
                        print("  -Mensagem enviada para {0}".format(data["destiny_id"]))
                        print("  -Mensagem mensagem: {0}".format(data["message"]))
                        # print("  -Mensagem criptografada: {0}".format(data["message_encrypted"]))
                        # print("  -Mensagem descriptografada: {0}".format(crypto.decrypt_RSA.data["message_encrypted"]))

                # File Receiver ---- FALTA TODA IMPLEMENTAÇÃO DAS FILAS E CONTROLE DE ARQUIVOS
                if data["type"] == "file":
                    if data["destiny_id"] == personal_id:  # Checa se a mensagem é para mim
                        print("Solicitação de arquivo recebida!")
                        if syscall("cat ./arquivos/lock")[0] == '1':
                            print("Arquivo em lock, acesso negado")
                            sock.sendto(b'ACESSO NEGADO - ARQUIVO BLOQUEADO', address)
                            no_ack = 1
                        print("Dando Lock em arquivo.")
                        syscall(
                            "echo 1 > ./arquivos/lock")  # Todo o lock de dados tem que ser refeito em objetos e nao em arquivos
                        file_data = syscall("cat ./arquivos/meu_arquivo")[0]
                        print("Responendo dado do arquivo: {0}".format(file_data))
                        sock.sendto(file_data.encode(), address)
                        no_ack = 1
                        time.sleep(4)
                        print("Removendo Lock de arquivo.")
                        syscall("echo 0 > ./arquivos/lock")
            if no_ack == 0:
                sock.sendto(b'ack', address)
