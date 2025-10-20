import hashlib
import random
import string
import time
from typing import Dict, Optional, List
import json
import itertools
import csv
from pathlib import Path
import pandas as pd



class RainbowTable:
    """
    Implementación de Tabla Arcoíris + ataque
    """
    
    def __init__(self, 
                 hash_bytes: int = 40,
                 t: int = 500,
                 n: int = 1000000,
                 pwd_length: int = 5,
                 charset: str = string.ascii_lowercase):
        """      
        Args:
        - hash_bytes: tamaño en bits del hash (SHA-256 truncado)
        - t: longitud de cadena en la tabla 
        - n: número de cadenas en la tabla
        - pwd_length: tamaño de contraseña objetivo
        - charset: dominio de caracteres permitidos
        """
        # Entrada
        self.hash_bytes = hash_bytes
        self.hash_bytes = hash_bytes * 8
        self.t = t
        self.n = n
        self.pwd_length = pwd_length        
        self.charset = charset

        # Utilidades
        self.charset_size = len(charset)
        self.table: Dict[str, str] = {}  # {hash_final: password_inicial}
        
        # Estadísticas
        self.construction_time = 0
        self.collisions_during_construction = 0
        
    def _hash(self, password: str) -> str:
        """
        Función hash: SHA-256 truncado a hash_bits.
        
        Args:
            - password: contraseña a hashear
            
        Returns:
            - Hash truncado como cadena hexadecimal
        """
        full_hash = hashlib.sha256(password.encode()).digest()
        trunc_hash = full_hash[:self.hash_bytes]
        return trunc_hash.hex()
    
    def _reduce(self, hash_string: str, iteration: int) -> str:
        """
        Función de reducción mejorada que mapea un hash a una contraseña válida.
        Usa desplazamiento por iteración para evitar puntos de fusión.
        
        Args:
            - hash_string: hash en formato hexadecimal
            - iteration: iteración actual en la cadena
            
        Returns:
            Contraseña reconstruida
        """
        # Desplazar el valor del hash por la iteración y módulo 2^hash_bits
        value = (int(hash_string, 16) + iteration) % (2 ** self.hash_bits)
        
        password = ''
        for _ in range(self.pwd_length):
            mod = value % self.charset_size
            value //= self.charset_size
            password += self.charset[mod]
        
        return password
    
    def _generate_random_password(self) -> str:
        """
        Genera una contraseña aleatoria del charset.
        
        Returns:
            - Contraseña aleatoria
        """
        return ''.join(random.choices(self.charset, k=self.pwd_length))
    
    def _get_end_of_chain(self, start_password: str) -> tuple[str, str]:
        """
        Obtiene el final de una cadena comenzando desde una contraseña inicial.
        
        Args:
            - start_password: contraseña inicial de la cadena
            
        Returns:
            - Tupla (hash_final, contraseña_inicial)
        """
        current = start_password
        current_hash = self._hash(current)
        
        for i in range(self.t):
            current = self._reduce(current_hash, i)
            current_hash = self._hash(current)
        
        # Retornar el hash final (no la contraseña final)
        return current_hash, start_password
    
    def build_table(self, verbose: bool = True) -> None:
        """
        Construye la tabla arcoíris siguiendo el algoritmo original
        pero usando la función de reducción mejorada.
        
        Args:
            - verbose: si es True, muestra el progreso
        """
        if verbose:
            print(f"Construyendo tabla arcoíris...")
            print(f"  Hash: SHA-256 truncado a {self.hash_bits} bits")
            print(f"  Longitud de cadena (t): {self.t}")
            print(f"  Número de cadenas (n): {self.n}")
            print(f"  Longitud de contraseña: {self.pwd_length}")
            print(f"  Charset: '{self.charset[:20]}{'...' if len(self.charset) > 20 else ''}'")
            print(f"  Espacio de claves: {self.charset_size}^{self.pwd_length} = {self.charset_size**self.pwd_length:,}")
        
        start_time = time.time()
        self.table.clear()
        self.collisions_during_construction = 0
        
        attempts = 0
        MAX_SECONDS = 60 # 1 minutots
        while len(self.table) < self.n:

            if time.time() - start_time > MAX_SECONDS:
                print(f"Se alcanzó el tiempo máximo de construcción ({MAX_SECONDS}s) para una tabla de {self.n=} x {self.t=}.")
                return f'Se ha alcanzo el máximo tiempo de construcción ({MAX_SECONDS}s) y se tienen {len(self.table)} entradas'
                  

            attempts += 1            
            start_pwd = self._generate_random_password()            
            end_hash, start_pwd = self._get_end_of_chain(start_pwd)
            
            if end_hash in self.table:
                self.collisions_during_construction += 1
                continue
            
            self.table[end_hash] = start_pwd
            
            if verbose and len(self.table) % max(1, self.n // 10) == 0:
                progress = (len(self.table) / self.n) * 100
                print(f"  Progreso: {progress:.1f}% ({len(self.table)}/{self.n})")
        
        self.construction_time = time.time() - start_time
        
        if verbose:
            print(f"\nTabla arcoíris construida en {self.construction_time:.2f} segundos")
            print(f"  Número de intentos: {attempts}")
            print(f"  Colisiones durante construcción: {self.collisions_during_construction}")
            print(f"  Tamaño de la tabla: {len(self.table)} entradas")
    
    def _get_partial_chain_end_hash(self, hash_string: str, start_iteration: int) -> str:
        """
        Calcula el hash final de una cadena parcial comenzando desde un hash
        en una iteración específica.
        
        Args:
            - hash_string: hash inicial
            - start_iteration: iteración desde donde empezar
            
        Returns:
            - Hash al final de la cadena parcial
        """
        current_hash = hash_string
        
        for i in range(start_iteration, self.t):
            current_pwd = self._reduce(current_hash, i)
            current_hash = self._hash(current_pwd)
        
        return current_hash
    
    def crack_password(self, target_hash: str, timeout: float = 60.0, verbose: bool = False) -> Optional[str]:
        """
        Busca una contraseña que produzca el hash objetivo.
        Implementación adaptada para trabajar con la nueva función de reducción.
        
        Args:
            - target_hash: hash objetivo (cadena hexadecimal)
            - timeout: tiempo máximo de búsqueda
            - verbose: si True, muestra información de debug
            
        Returns:
            - Contraseña encontrada o None
        """
        if verbose:
            print(f"\nBuscando colisión para hash: {target_hash}")
        
        start_time = time.time()
        
        for i in range(self.t - 1, -1, -1):
            if time.time() - start_time > timeout:
                if verbose:
                    print(f"Timeout alcanzado: ({timeout}s)")
                return None
            
            end_hash = self._get_partial_chain_end_hash(target_hash, i)
            
            if end_hash in self.table:
                if verbose:
                    print(f"Posible cadena encontrada en iteración {i}")
                
                start_pwd = self.table[end_hash]
                current_pwd = start_pwd
                
                for step in range(self.t + 1):
                    current_hash = self._hash(current_pwd)
                    
                    if current_hash == target_hash:
                        if verbose:
                            elapsed = time.time() - start_time
                            print(f" Contraseña encontrada: '{current_pwd}' en {elapsed:.3f}s")
                        return current_pwd
                    
                    if step < self.t:
                        current_pwd = self._reduce(current_hash, step)
                    
                    if time.time() - start_time > timeout:
                        if verbose:
                            print(f"Timeout durante reconstrucción de cadena")
                        return None
        
        if verbose:
            print(f" Contraseña no encontrada en la tabla")
        return None
    
    def crack_password_from_string(self, password: str, timeout: float = 60.0, verbose: bool = False) -> Optional[str]:
        """
        Intenta crackear una contraseña dada calculando su hash y buscando una colisión.
        
        Args:
            - password: contraseña a atacar
            - timeout: tiempo máximo de búsqueda
            - verbose: si True, se mostrará información

        Returns:
            - Contraseña alternativa encontrada o None
        """
        target_hash = self._hash(password)
        if verbose:
            print(f"Atacando contraseña: '{password}'")
            print(f"Hash objetivo: {target_hash}")
        
        return self.crack_password(target_hash, timeout, verbose)
    
    def run_experiment(self, num_tests: int = 100, test_passwords: Optional[List[str]] = None, 
                      timeout: float = 60.0) -> Dict:
        """
        Ejecuta un experimento completo.
        
        Args:
            - num_tests: número de contraseñas a testear
            - test_passwords: lista de contraseñas específicas (opcional)
            - timeout: timeout por intento de crackeo
            
        Returns:
            - Diccionario con estadísticas 
        """
        print(f"\n{'='*60}")
        print(f"Ejecutando experimento")
        print(f"{'='*60}")
        
        if test_passwords is None:
            test_passwords = [self._generate_random_password() for _ in range(num_tests)]
            print(test_passwords)
        else:
            num_tests = len(test_passwords)
        
        results = {
            'total_tests': num_tests,
            'successful_cracks': 0,
            'failed_cracks': 0,
            'timeouts': 0,
            'success_rate': 0.0,
            'total_time': 0.0,
            'avg_time_per_crack': 0.0,
            'avg_time_successful': 0.0,
            'successful_examples': [],
            'timeout_setting': timeout,
            'table_info': {
                'hash_bits': self.hash_bits,
                'chain_length': self.t,
                'num_chains': self.n,
                'pwd_length': self.pwd_length,
                'charset_size': self.charset_size,
                'construction_time': self.construction_time,
                'collisions': self.collisions_during_construction
            }
        }
        
        start_time = time.time()
        successful_times = []
        
        for i, pwd in enumerate(test_passwords):
            if (i + 1) % max(1, num_tests // 10) == 0:
                print(f"Progreso: {((i+1)/num_tests)*100:.1f}% ({i+1}/{num_tests})")
            
            crack_start = time.time()
            cracked = self.crack_password_from_string(pwd, timeout=timeout, verbose=False)
            crack_time = time.time() - crack_start
            
            if cracked is not None:
                results['successful_cracks'] += 1
                successful_times.append(crack_time)
                if len(results['successful_examples']) < 10:
                    results['successful_examples'].append({
                        'original': pwd,
                        'cracked': cracked,
                        'time': crack_time,
                        'same': pwd == cracked
                    })
            else:
                results['failed_cracks'] += 1
                if crack_time >= timeout * 0.95:  
                    results['timeouts'] += 1
        
        results['total_time'] = time.time() - start_time
        results['success_rate'] = (results['successful_cracks'] / num_tests) * 100
        results['avg_time_per_crack'] = results['total_time'] / num_tests
        if successful_times:
            results['avg_time_successful'] = sum(successful_times) / len(successful_times)
        
        print(f"\n{'='*60}")
        print(f"Resultados del experimento")
        print(f"{'='*60}")

        print(f"Número de tests: {results['total_tests']}")
        print(f"Éxitos: {results['successful_cracks']}")
        print(f"Fallos: {results['failed_cracks']}")
        print(f"Timeouts: {results['timeouts']}")
        print(f"Tasa de éxito: {results['success_rate']:.2f}%")
        print(f"Tiempo total: {results['total_time']:.2f}s")
        print(f"Tiempo promedio por intento: {results['avg_time_per_crack']*1000:.2f}ms")
        if results['avg_time_successful'] > 0:
            print(f"Tiempo promedio (solo éxitos): {results['avg_time_successful']*1000:.2f}ms")
        
        if results['successful_examples']:
            print(f"\nEjemplos de colisiones encontradas:")
            for ex in results['successful_examples'][:5]:
                match = "Misma" if ex['same'] else "Diferente"
                print(f"  '{ex['original']}' -> '{ex['cracked']}' [{match}] ({ex['time']*1000:.2f}ms)")
        
        return results
    
    def save_table(self, filename: str) -> None:
        """Guarda la tabla en un archivo"""
        data = {
            'params': {
                'hash_bits': self.hash_bits,
                'chain_length': self.t,
                'num_chains': self.n,
                'pwd_length': self.pwd_length,
                'charset': self.charset
            },
            'table': self.table
        }
        with open(filename, 'w') as f:
            json.dump(data, f)
        print(f"Tabla arcoíris guardada en {filename}")
    
    def load_table(self, filename: str) -> None:
        """Carga la tabla desde un archivo"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        params = data['params']
        self.hash_bytes = params['hash_bytes']
        self.hash_bits = self.hash_bits * 8
        self.t = params['chain_length']
        self.n = params['num_chains']
        self.pwd_length = params['pwd_length']
        self.charset = params['charset']
        self.charset_size = len(self.charset)
        self.table = data["table"]
        print(f"Tabla arcoíris cargada desde {filename} ({len(self.table)} entradas)")





def main():

    def append_row_to_csv(path: Path, row: dict, header: list):
        """
        Función auxiliar para añadir filas a un fichero csv
        """
        write_header = not path.exists()
        with path.open("a", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if write_header:
                writer.writeheader()
            writer.writerow(row)



    def combination_done(df_done: pd.DataFrame, n: int, t:int, trunc:int, pwd_len:int, seed_idx:int, seed:int) -> bool:
        """
        Función auxiliar para saber si una fila existe
        """
        mask = (
            (df_done["n"] == n) &
            (df_done["t"] == t) &
            (df_done["trunc_bytes"] == trunc) &
            (df_done["pwd_length"] == pwd_len) &
            (df_done["seed_index"] == seed_idx) &
            (df_done["seed"] == seed)
        )
        return mask.any()


    N_VALUES = [100, 500, 1000, 5000, 10000, 50000, 100000]  
    T_VALUES = [100, 200, 300, 400, 500]       
    TRUNC_BYTES = [4, 5, 6]                    
    PWD_LENGTHS = [5, 7, 10]               
    SEEDS = [1, 123, 999]                  
    PWD_PER_SET = 100
    CHARSET = string.ascii_lowercase
    OUT_CSV = Path("rainbow_grid_results.csv")
    COLUMNS = [
        "seed_index", "seed", "n", "t", "trunc_bytes", "hash_bits",
        "pwd_length", "successful_cracks", "failed_cracks",
        "total_time", "success_rate", "avg_time_per_crack",
        "same", "different", "construction_time", "notes", "timestamp"
    ]

    if not OUT_CSV.exists():
        pd.DataFrame(columns=COLUMNS).to_csv(OUT_CSV, index=False)


    grid_iter = itertools.product(N_VALUES, T_VALUES, TRUNC_BYTES, PWD_LENGTHS, enumerate(SEEDS))
    total_combinations = len(N_VALUES) * len(T_VALUES) * len(TRUNC_BYTES) * len(PWD_LENGTHS) * len(SEEDS)
    print(f"Total combinacions: {total_combinations}")

    combo_count = 0
    for (n, t, trunc_b, pwd_len, (seed_idx, seed)) in grid_iter:

        combo_count += 1
        if combination_done(n, t, trunc_b, pwd_len, seed_idx, seed):
            print(n, t, trunc_b, pwd_len, seed_idx, seed)
            continue  


        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{combo_count}/{total_combinations}] seed={seed} (idx {seed_idx}) n={n} t={t} trunc={trunc_b} pwd_len={pwd_len}")

        rainbow = RainbowTable(
            hash_bytes=trunc_b,
            t=t,
            n=n,
            pwd_length=pwd_len,
            charset=CHARSET
        )

        row = {
            "seed_index": seed_idx,
            "seed": seed,
            "n": n,
            "t": t,
            "trunc_bytes": trunc_b,
            "hash_bits": trunc_b*8,
            "pwd_length": pwd_len,
            "successful_cracks": None,
            "failed_cracks": None,
            "total_time": None,
            "success_rate": None,
            "avg_time_per_crack": None,
            "same": None,
            "different": None,
            "construction_time": None,
            "notes": "",
            "timestamp": timestamp
        }

        try:
            t0 = time.time()

            global_state = random.getstate()
            random.seed(seed + combo_count)

            try:
                note_rainbow = rainbow.build_table(verbose=False)
                results = rainbow.run_experiment(
                    num_tests=PWD_PER_SET,
                    timeout=60.0
                )
            finally:
                random.setstate(global_state)

            t1 = time.time()
            total_time = t1 - t0

            row["successful_cracks"] = results.get("successful_cracks")
            row["failed_cracks"] = results.get("failed_cracks")
            row["total_time"] = results.get("total_time", total_time)
            row["success_rate"] = results.get("success_rate")
            row["avg_time_per_crack"] = results.get("avg_time_per_crack")
            # Comptar same/different
            same = 0; different = 0
            for sample in results.get("successful_examples", []):
                if sample.get("same"):
                    same += 1
                else:
                    different += 1
            row["same"] = same
            row["different"] = different
            row["construction_time"] = results.get("table_info", {}).get("construction_time")

            if note_rainbow:
                row["notes"] = note_rainbow
            else:
                row["notes"] = "OK"
        except Exception as e:
            row["notes"] = f"ERROR: {type(e).__name__}: {e}"
            print("  Error en aquesta combinació:", e)

        append_row_to_csv(OUT_CSV, row, COLUMNS)

    df = pd.read_csv(OUT_CSV)
    print("Experiments stored at:", OUT_CSV)
    print(df.head())

if __name__ == "__main__":
    main()


