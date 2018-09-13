import socket
import struct
from datetime import datetime

from crypto import crypto


class Sender():

    @staticmethod
    def multicastMessageSender(message, destiny, ip, porta, personal_id):
        '''
        mensagem e o dado sem criptografica
        destiny e o mac do destinatario
        '''
        # Criptografa a mensagem e retorna na variavel, ex:
        # destiny_key = syscall("cat ./others_keys/{0}".format(destiny_key_address))[0]
        destiny_key_address = "{0}@{0}.pub".format(destiny)
        message_cryp_dest = crypto.encrypt_RSA("./others_keys/{0}".format(destiny_key_address),
                                               message)  # Mensagem criptografada na chave do destinatario
        message_cryp_MINE = crypto.encrypt_RSA("./my_keys/id_rsa.pub",
                                               message)  # Mensagem critpografada na minha própria chave
        message_decripted_MINE = crypto.decrypt_RSA("./my_keys/id_rsa",
                                                    message_cryp_MINE)  # Minha mensagem descriptografada
        # message = crypto.encrypt_RSA("./my_keys/b827eb6cfa20@b827eb6cfa20.pub", message)
        print("\n\n--Demosntração do dado pós criptografia na chave pública do destinatario: {0}".format(
            message_cryp_dest))
        # print("\n\n--Demosntração do dado pós criptografia na MINHA propria chave PÚBLICA: {0}".format(message_cryp_MINE))
        # print("\n\n--Demosntração do dado pós DEScriptografica na MINHA própria chave PRIVADA: {0}".format(message_decripted_MINE))

        multicast_group = (str(ip), int(porta))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set a timeout so the socket does not block
        # indefinitely when trying to receive data.
        sock.settimeout(2)
        # Set the time-to-live for messages to 1 so they do not
        # go past the local network segment.
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        try:  # Look for responses from all recipients
            while True:
                print("\n\n-----MESSAGE SENDED-----")
                # JSON com o id da maquina que é seu MAC e sus public_key
                print(message)
                message = {'sender_id': personal_id, 'destiny_id': destiny, 'message': message,
                           'message_encrypted': "AQUI VAI A variavel message_crip_dest",
                           'time': datetime.now().strftime("%H:%M:%S"), 'type': 'encrypted-message'}
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

    @staticmethod
    def multicastSender(ip, porta, personal_id, key):
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

        try:  # Look for responses from all recipients
            # while True:
            print("\n\n-----KEY SENDED-----")
            # JSON com o id da maquina que é seu MAC e sus public_key
            message = {'id': personal_id, 'key': key, 'time': datetime.now().strftime("%H:%M:%S"), 'type': 'key'}
            # Send data to the multicast group
            print('sending {0}'.format(message))
            sent = sock.sendto(str(message).encode('utf-8'), multicast_group)
            try:
                data, server = sock.recvfrom(16)
                print('Recebido {!r} de {}'.format(data, server))
            except socket.timeout:
                print("Sem respostas - Timeout")
            # break
            # time.sleep(60)
        finally:
            print('Closing socket')
            sock.close()
