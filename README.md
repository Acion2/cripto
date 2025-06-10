# cripto
Trabalho de Segurança de Sistemas
1. Importações:
Python
import hashlib
import os
from google.colab import files
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

hashlib: Fornece funções para trabalhar com algoritmos de hash, como SHA-256, que é usado no PBKDF2 para derivar a chave.
os: Oferece funcionalidades do sistema operacional, como gerar dados aleatórios (os.urandom) para criar o salt.
from google.colab import files: Módulo específico do Google Colab que permite interagir com arquivos, como fazer download dos arquivos gerados.
import tkinter as tk: Biblioteca padrão do Python para criar interfaces gráficas. Embora neste código para Colab a seleção de arquivos seja feita via nome digitado, a importação é mantida para evitar possíveis erros em outros ambientes.
from tkinter import filedialog: Submódulo do tkinter que fornece diálogos comuns de arquivo (como a janela de "Abrir").
from tkinter import messagebox: Submódulo do tkinter para exibir caixas de mensagens (para mostrar erros ou sucesso).
2. gerar_chave_salt(senha):
Python
def gerar_chave_salt(senha):
    """Gera um salt aleatório e uma chave derivada usando PBKDF2."""
    salt = os.urandom(16)
    chave = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, 100000)
    return chave, salt

Esta função tem como objetivo criar uma chave criptográfica segura a partir de uma senha fornecida pelo usuário.
salt = os.urandom(16): Gera 16 bytes de dados aleatórios. O salt é um valor aleatório que é combinado com a senha antes de ser hasheada. Isso torna ataques de dicionário e tabelas precomputadas (rainbow tables) muito mais difíceis.
chave = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, 100000): Utiliza a função pbkdf2_hmac do módulo hashlib.
'sha256': Especifica o algoritmo de hash a ser usado (SHA-256).
senha.encode('utf-8'): Converte a senha (string) para bytes usando a codificação UTF-8, pois as funções de hash operam em bytes.
salt: O salt gerado anteriormente.
100000: O número de iterações. Quanto maior esse número, mais computacionalmente caro é gerar a chave (e, portanto, mais difícil para um atacante tentar adivinhar a senha por força bruta).
A função retorna a chave derivada (em bytes) e o salt (em bytes).
3. cifrar_rail_fence(texto, trilhos):
Python
def cifrar_rail_fence(texto, trilhos):
    """Cifra um texto usando a Cifra de Trilho de Ferro."""
    matriz = [['' for _ in range(len(texto))] for _ in range(trilhos)]
    direcao = 1  # 1 para baixo, -1 para cima
    linha, coluna = 0, 0

    for char in texto:
        matriz[linha][coluna] = char
        coluna += 1
        linha += direcao

        if linha == trilhos - 1 or linha == 0:
            direcao *= -1

    texto_cifrado = ''.join(''.join(row) for row in matriz)
    return texto_cifrado

Implementa o algoritmo de criptografia da Cifra de Trilho de Ferro.
Cria uma matriz bidimensional (matriz) para simular os "trilhos".
Percorre o texto caractere por caractere, escrevendo-os na matriz em um padrão zigue-zague, determinado pela variável direcao e pelo número de trilhos.
Finalmente, lê a matriz linha por linha e junta os caracteres para formar o texto_cifrado.
4. decifrar_rail_fence(texto_cifrado, trilhos):
Python
def decifrar_rail_fence(texto_cifrado, trilhos):
    """Decifra um texto usando a Cifra de Trilho de Ferro."""
    matriz = [['' for _ in range(len(texto_cifrado))] for _ in range(trilhos)]
    direcao = 1
    linha, coluna = 0, 0

    # Preenche a matriz com marcadores para identificar a ordem das letras
    for _ in range(len(texto_cifrado)):
        matriz[linha][coluna] = '*'
        coluna += 1
        linha += direcao
        if linha == trilhos - 1 or linha == 0:
            direcao *= -1

    # Preenche a matriz com as letras do texto cifrado na ordem correta
    indice = 0
    texto_decifrado_matriz = [['' for _ in range(len(texto_cifrado))] for _ in range(trilhos)]
    for i in range(trilhos):
        for j in range(len(texto_cifrado)):
            if matriz[i][j] == '*':
                texto_decifrado_matriz[i][j] = texto_cifrado[indice]
                indice += 1

    # Lê a matriz na ordem correta para obter o texto decifrado
    texto_decifrado = ''
    linha, coluna = 0, 0
    direcao = 1
    for _ in range(len(texto_cifrado)):
        texto_decifrado += texto_decifrado_matriz[linha][coluna]
        coluna += 1
        linha += direcao
        if linha == trilhos - 1 or linha == 0:
            direcao *= -1

    return texto_decifrado

Implementa o algoritmo de decriptografia da Cifra de Trilho de Ferro.
Cria uma matriz com as mesmas dimensões usadas na cifragem.
Na primeira passagem pela matriz, marca as posições onde os caracteres do texto cifrado devem ser colocados, seguindo o padrão zigue-zague.
Na segunda passagem, preenche essas posições com os caracteres do texto_cifrado em ordem.
Finalmente, lê a matriz no mesmo padrão zigue-zague para obter o texto_decifrado (texto plano original).
5. cifrar_arquivo(nome_arquivo, senha, trilhos):
Python
def cifrar_arquivo(nome_arquivo, senha, trilhos):
    """Cifra o conteúdo de um arquivo texto usando Rail Fence e PBKDF2."""
    try:
        with open(nome_arquivo, 'r') as arquivo:
            texto_plano = arquivo.read()
    except FileNotFoundError:
        print(f"Erro: Arquivo '{nome_arquivo}' não encontrado.")
        return None, None

    chave, salt = gerar_chave_salt(senha)
    texto_cifrado = cifrar_rail_fence(texto_plano, trilhos)

    nome_arquivo_base = os.path.splitext(os.path.basename(nome_arquivo))[0]
    nome_arquivo_cifrado = f"{nome_arquivo_base}_cifrado.txt"

    try:
        with open(nome_arquivo_cifrado, 'w') as arquivo_cifrado:
            arquivo_cifrado.write(f"{salt.hex()}${trilhos}${texto_cifrado}")
        print(f"Arquivo '{nome_arquivo}' cifrado com sucesso para '{nome_arquivo_cifrado}'.")
        return nome_arquivo_cifrado, texto_cifrado
    except Exception as e:
        print(f"Erro ao escrever no arquivo cifrado: {e}")
        return None, None

Função para cifrar o conteúdo de um arquivo.
Tenta abrir o arquivo especificado em modo de leitura ('r'). Se o arquivo não for encontrado, exibe um erro.
Chama gerar_chave_salt para obter o salt e a chave derivada da senha.
Chama cifrar_rail_fence para cifrar o texto do arquivo.
Cria um novo nome de arquivo para o arquivo cifrado (adicionando _cifrado ao nome original).
Tenta abrir um novo arquivo em modo de escrita ('w') e escreve nele o salt (convertido para hexadecimal usando .hex()), o número de trilhos e o texto_cifrado, separados por um delimitador ($).
Retorna o nome do arquivo cifrado e o texto cifrado em caso de sucesso, ou None, None em caso de erro.
6. decifrar_arquivo(nome_arquivo_cifrado, senha):
Python
def decifrar_arquivo(nome_arquivo_cifrado, senha):
    """Decifra o conteúdo de um arquivo cifrado com Rail Fence e PBKDF2."""
    try:
        with open(nome_arquivo_cifrado, 'r') as arquivo_cifrado:
            conteudo_cifrado = arquivo_cifrado.read().split('$', 2)
            salt_hex = conteudo_cifrado[0]
            trilhos = int(conteudo_cifrado[1])
            texto_cifrado = conteudo_cifrado[2]
    except FileNotFoundError:
        print(f"Erro: Arquivo '{nome_arquivo_cifrado}' não encontrado.")
        return None, None
    except ValueError:
        print("Erro: Formato do arquivo cifrado inválido.")
        return None, None

    salt = bytes.fromhex(salt_hex)
    chave_derivada = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, 100000)

    nome_arquivo_base = os.path.splitext(os.path.basename(nome_arquivo_cifrado))[0].replace("_cifrado", "")
    nome_arquivo_decifrado = f"{nome_arquivo_base}_decifrado.txt"

    texto_decifrado = decifrar_rail_fence(texto_cifrado, trilhos)
    try:
        with open(nome_arquivo_decifrado, 'w') as arquivo_decifrado:
            arquivo_decifrado.write(texto_decifrado)
        print(f"Arquivo '{nome_arquivo_cifrado}' decifrado com sucesso para '{nome_arquivo_decifrado}'.")
        return nome_arquivo_decifrado, texto_decifrado
    except Exception as e:
        print(f"Erro ao escrever no arquivo decifrado: {e}")
        return None, None

Função para decifrar o conteúdo de um arquivo cifrado.
Tenta abrir o arquivo cifrado em modo de leitura.
Lê o conteúdo do arquivo e o divide usando o delimitador ($) para extrair o salt (que está em formato hexadecimal e precisa ser convertido de volta para bytes usando bytes.fromhex()), o número de trilhos (convertido para inteiro) e o texto_cifrado.
Recalcula a chave derivada usando a senha fornecida e o salt extraído do arquivo.
Chama decifrar_rail_fence para decifrar o texto cifrado usando o número de trilhos correto.
Cria um novo nome de arquivo para o arquivo decifrado (substituindo _cifrado por _decifrado no nome original).
Tenta abrir um novo arquivo em modo de escrita e escreve nele o texto_decifrado.
Retorna o nome do arquivo decifrado e o texto decifrado em caso de sucesso, ou None, None em caso de erro.
7. Bloco if __name__ == "__main__"::
Python
if __name__ == "__main__":
    while True:
        acao = input("Digite 'cifrar' para cifrar um arquivo, 'decifrar' para decifrar (ou 'sair' para encerrar): ").lower()
        if acao == 'cifrar':
            print("Digite o nome do arquivo a ser cifrado (certifique-se de que ele foi carregado no Colab):")
            nome_arquivo = input()
            senha = input("Digite a senha para cifrar: ")
            while True:
                try:
                    trilhos = int(input("Digite o número de 'trilhos' para a cifra: "))
                    if trilhos > 1:
                        break
                    else:
                        print("O número de trilhos deve ser maior que 1.")
                except ValueError:
                    print("Por favor, digite um número inteiro válido para os trilhos.")
            nome_arquivo_cifrado, texto_cifrado = cifrar_arquivo(nome_arquivo, senha, trilhos)
            if nome_arquivo_cifrado:
                print(f"Arquivo cifrado salvo como '{nome_arquivo_cifrado}'.")
                # Opcional: fazer o download do arquivo cifrado
                # files.download(nome_arquivo_cifrado)
        elif acao == 'decifrar':
            print("Digite o nome do arquivo a ser decifrado (certifique-se de que ele foi carregado no Colab):")
            nome_arquivo_cifrado = input()
            senha = input("Digite a senha para decifrar: ")
            nome_arquivo_decifrado, texto_decifrado = decifrar_arquivo(nome_arquivo_cifrado, senha)
            if nome_arquivo_decifrado:
                print(f"Arquivo decifrado salvo como '{nome_arquivo_decifrado}'.")
                # Opcional: fazer o download do arquivo decifrado
                # files.download(nome_arquivo_decifrado)
        elif acao == 'sair':
            break
        else:
            print("Ação inválida. Por favor, digite 'cifrar', 'decifrar' ou 'sair'.")

Este bloco de código é executado quando o script é rodado diretamente.
Entra em um loop infinito (while True) para permitir que o usuário realize múltiplas operações (cifrar ou decifrar) até escolher sair.
Pede ao usuário para digitar a ação desejada (cifrar, decifrar ou sair).
Se a ação for cifrar:
Pede o nome do arquivo a ser cifrado (assumindo que ele já foi carregado no Google Colab).
Pede a senha para a cifragem.
Pede o número de trilhos para a Cifra de Trilho de Ferro, garantindo que seja maior que 1.
Chama a função cifrar_arquivo.
Se a cifragem for bem-sucedida, informa o nome do arquivo cifrado e oferece a opção de download (comentada).
Se a ação for decifrar:
Pede o nome do arquivo a ser decifrado (assumindo que ele já foi carregado no Google Colab).
Pede a senha para a decifragem.
Chama a função decifrar_arquivo.
Se a decifragem for bem-sucedida, informa o nome do arquivo decifrado e oferece a opção de download (comentada).
Se a ação for sair, o loop é interrompido (break) e o programa termina.
Se a ação digitada não for válida, exibe uma mensagem de erro.

