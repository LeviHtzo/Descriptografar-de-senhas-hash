import hashlib
import itertools
import string
import time
from tqdm import tqdm

HASH_TYPES = {
    'md4': 32,
    'md5': 32,
    'sha1': 40,
    'sha224': 56,
    'sha256': 64,
    'sha384': 96,
    'sha512': 128,
    'sha3_224': 56,
    'sha3_256': 64,
    'sha3_384': 96,
    'sha3_512': 128,
    'ripemd160': 40,
    'blake2b512': 128,
}

def detect_hash_type(hash_value):
    for hash_name, hash_length in HASH_TYPES.items():
        if len(hash_value) == hash_length:
            return hash_name
    return None

def crack_hash(hash_value, hash_type):
    # Tentativa de força bruta para descriptografar o hash
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    
    start_time = time.time()
    length = 1
    while True:
        total_combinations = len(charset) ** length
        for guess in tqdm(itertools.product(charset, repeat=length), total=total_combinations, desc=f"Trying length {length}"):
            guess = ''.join(guess)
            try:
                hashed_guess = hashlib.new(hash_type, guess.encode()).hexdigest()
            except ValueError:
                continue
            
            if hashed_guess == hash_value:
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(f"\nTempo decorrido: {elapsed_time:.2f} segundos")
                return guess
        length += 1

def main():
    print("Tipos de hash suportados:")
    print("MD4")
    print("MD5")
    print("SHA1")
    print("SHA2-224")
    print("SHA2-256")
    print("SHA2-384")
    print("SHA2-512")
    print("SHA3-224")
    print("SHA3-256")
    print("SHA3-384")
    print("SHA3-512")
    print("RIPEMD-160")
    print("BLAKE2b-512")

    print("\nPara mais informações, visite o link: https://github.com/LeviHtzo/LeviHtzo")
    print("Faça uma doação!")
    print("Vaquinha link: https://www.vakinha.com.br/vaquinha/pensamentos-soltos")
    print("Faça uma doação! Aceitamos também Bitcoin: 1127qjBCvmdTV4otm9ntjiCb1qh9LGoN4q")

    print("\nDigite o hash que deseja descriptografar:")
    hash_input = input().strip()
    
    hash_type = detect_hash_type(hash_input)
    if not hash_type:
        print("Tipo de hash não suportado ou hash inválido.")
        return
    
    print(f"Detectado tipo de hash: {hash_type}")
    
    result = crack_hash(hash_input, hash_type)
    
    if result:
        print(f"Senha encontrada: {result}")
    else:
        print("Senha não encontrada.")

if __name__ == "__main__":
    main()

