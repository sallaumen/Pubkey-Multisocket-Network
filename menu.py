import threading

from receiver import Receiver
from sender import Sender


def syscall(p_command):
    v_subProcess = subprocess.run(p_command, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    return v_subProcess.stdout.decode('utf-8').split('\n')[:-1]



class Menu():
    def __init__(self, syscall, ip, porta, personal_id, key):
        self.key = key
        self.porta = porta
        self.ip = ip
        self.syscall = syscall
        self.personal_id = personal_id

        self.menu()

    def menu(self):
        menu_var = input(
            "\n    -[1] Escutar e enviar dados"
            "\n    -[2] Enviar menssagem"
            "\n    -[3] Enviar arquivo"
            "\n    -[Outras teclas] Finalizar o programa\n    : ")

        if menu_var == "1":
            clean_keys = input("    -Deseja apagar as keys atuais? (Y/N) ")
            if clean_keys == "Y":
                print("     Limpando keys atuais")
                self.syscall("rm ./others_keys/*")
            thread_receive = threading.Thread(target=Receiver.multicastReceiver, args=(self.ip,
                                                                                       self.porta,
                                                                                       self.personal_id))
            thread_receive.start()
            thread_sender = threading.Thread(target=Sender.multicastSender,
                                             args=(self.ip, self.porta, self.personal_id, self.key))
            thread_sender.start()
            return self.menu()

        elif menu_var == "2":
            print("\n    |--As opções de destinatários são: ")
            for i in self.syscall("ls -l ./others_keys/ | grep .pub"):
                i = i.split(" ")[8].split("@")[0]
                print("    |---> {0}".format(i))
            destino_valido = 0

            while (destino_valido == 0):
                destiny = input("    |---Coloque o nome do destino: ")
                destiny_key_address = "{0}@{0}.pub".format(destiny)
                try:
                    destiny_key = self.syscall("cat ./others_keys/{0}".format(destiny_key_address))[0]
                    destino_valido = 1
                except:
                    print("    |---X Destino inválido, chave não encontrada")
                    destino_valido = 0

            message = input("    |---Coloque a mensagem que deseja enviar: ")

            Sender.multicastMessageSender(message, destiny, self.ip, self.porta, self.personal_id)
            return self.menu()

        elif menu_var == "3":
            print("\n    |--As opções de destinatários são: ")
            for i in self.syscall("ls -l ./others_keys/ | grep .pub"):
                i = i.split(" ")[8].split("@")[0]
                print("    |---> {0}".format(i))
            destino_valido = 0
            while (destino_valido == 0):
                destiny = input("    |---Coloque o nome do destino: ")
                destiny_key_address = "{0}@{0}.pub".format(destiny)
                try:
                    destiny_key = self.syscall("cat ./others_keys/{0}".format(destiny_key_address))[0]
                    destino_valido = 1

                except:
                    print("    |---X Destino inválido, chave não encontrada")
                    destino_valido = 0
            Receiver.multicastArchiveRequest(destiny, self.ip, self.porta, self.personal_id, self.key)

            return self.menu()

        else:
            exit()
