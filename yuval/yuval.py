import hashlib
import time
from typing import Tuple, Optional, Dict
import os
import psutil

class Yuval:
    """
    Implementación del algoritmo de Yuval para encontrar colisiones.
    Este algoritmo explota la paradoja del cumpleaños para encontrar 
    dos mensajes semánticamente diferentes que producen el mismo hash.
    """
    
    def __init__(self, 
                 hash_bytes: int = 5,
                 timeout: Optional[float] = None):
        """        
        Args:
            - hash_bytes: número de Bytes al que truncar la función resumen
            - timeout: máximo tiempo en segundos para encontrar una colsión. Por defecto, None
        """
        self.hash_bytes = hash_bytes
        self.timeout = timeout
        self.hash_table: Dict[str, str] = {}
        
        
    def _hash(self, text: str) -> str:
        """
        Función hash: SHA-256 truncado a hash_bits.
        
        Args:
            - text: texto del que obtener la función resumen
            
        Returns:
            - Hash truncado como cadena hexadecimal
        """
        full_hash = hashlib.sha256(text.encode()).digest()
        trunc_hash = full_hash[:self.hash_bytes]
        return trunc_hash.hex()
    
    def generate_variations(self, base_message:str, max_variations: int, dic_variations:dict):
        from itertools import product
        words = base_message.split()
        variants_lists = [dic_variations.get(w, [w]) for w in words]
        texts = []

        for i,combination in enumerate(product(*variants_lists)):
            texts.append((" ".join(combination)))
            if i > max_variations:
                return texts


    def find_collision(self, 
                      legitimate_message: str,
                      illegitimate_message: str, 
                      variations_l: dict , 
                      variations_i: dict) -> Tuple[Optional[str], Optional[str], dict]:
        """
        Busca una colisión entre dos mensajes diferentes usando el algoritmo de Yuval

        Algoritmo:
        1. Generar t = 2^(m/2) modificaciones de x_l
        2. Calcular y almacenar los hash (x_l, hash(x_l))
        3. Generar modificaciones del texto x_i hasta encontrar colisión o timeout

        Args:
            - legitimate_message: mensaje que normalmente se firmaría
            - illegitimate_message: mensaje malicioso que se busca firmar
            
        Returns:
            - Tuple de (variante_legítima, variante_ilegítima, estadísticas)
            - Returns (None, None, stats) si no encuentra nada
        """
        t = 2 ** (self.hash_bytes*8 // 2)
        
        stats = {
            'legitimate_variations': 0,
            'illegitimate_attempts': 0,
            'total_hashes': 0,
            'time_elapsed': 0,
            'collision_found': False,
            'hash_bytes': self.hash_bytes,
}
        
        start_time = time.time()
        
        # Step 1:
        print(f"Generating {t} variations of legitimate message...")
        legitimate_variations = self.generate_variations(legitimate_message, t, variations_l)
        
        # Step 2:
        self.hash_table.clear()
        for variation in legitimate_variations:
            hash_val = self._hash(variation)

            if hash_val not in self.hash_table:
                self.hash_table[hash_val] = variation
            stats['legitimate_variations'] += 1
            stats['total_hashes'] += 1
        
        print(f"Built hash table with {len(self.hash_table)} unique hashes")
        
        # Step 3-6:
        print(f"Searching for collision (expected around {t} attempts)...")
        
        illegitimate_variations = self.generate_variations(illegitimate_message, t, variations_i)
        
        for i, illegitimate_var in enumerate(illegitimate_variations):
            # Check timeout
            if self.timeout and (time.time() - start_time) > self.timeout:
                print("Timeout reached!")
                break
                
            hash_val = self._hash(illegitimate_var)
            stats['illegitimate_attempts'] += 1
            stats['total_hashes'] += 1
            
            # Check for collision
            if hash_val in self.hash_table:
                legitimate_var = self.hash_table[hash_val]
                stats['collision_found'] = True
                stats['time_elapsed'] = time.time() - start_time
                
                print(f"\n COLLISION FOUND after {i+1} attempts!")
                print(f"Hash: {hash_val}")
                print(f"Time: {stats['time_elapsed']:.2f} seconds")
                
                return legitimate_var, illegitimate_var, stats
            
            # Progress update
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"  Attempts: {i+1}, Time: {elapsed:.2f}s")
        
        stats['time_elapsed'] = time.time() - start_time
        print(f"\n No collision found after {stats['illegitimate_attempts']} attempts")
        
        return None, None, stats
    
    def verify_collision(self, msg1: str, msg2: str) -> bool:
        """
        Verifica que dos mensajes tienen el mismo hash

        Args:
            - msg1: primer mensaje
            - msg2: segundo mensaje
            
        Returns:
            True si los hashes hacen match, False en caso contrario
        """
        hash1 = self._hash(msg1)
        hash2 = self._hash(msg2)
        
        print(f"\nVerification:")
        print(f"Message 1 hash: {hash1}")
        print(f"Message 2 hash: {hash2}")
        print(f"Match: {hash1 == hash2}")
        
        return hash1 == hash2


if __name__ == "__main__":

    print("=" * 60)
    print("Yuval")
    print("=" * 60)
    
    yuval = Yuval(
        hash_bytes=5, 
        timeout=60
    )
    
    legit_var, illegit_var, stats = yuval.find_collision(
        texto_l, 
        texto_i,
        variations_l,
        variations_i
    )
    
    # Display results
    if legit_var and illegit_var:
        print("\n" + "=" * 60)
        print("COLLISION FOUND!")
        print("=" * 60)
        print(f"\nLegitimate variant:\n'{legit_var}'")
        print(f"\nIllegitimate variant:\n'{illegit_var}'")
        
        yuval.verify_collision(legit_var, illegit_var)
    
    # Display statistics
    print("\n" + "=" * 60)
    print("Statistics:")
    print("=" * 60)
    for key, value in stats.items():
        print(f"{key}: {value}")

    process = psutil.Process(os.getpid())
    mem = process.memory_info().rss / 1024**2  
    print(f"\nMemoria RAM usada: {mem:.2f} MB")
