import re
import sys
import os
import random
import string
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Go reserved words that should NOT be modified
RESERVED = {
    'break', 'default', 'func', 'interface', 'select', 'case', 'defer', 'go',
    'map', 'struct', 'chan', 'else', 'goto', 'package', 'switch', 'const',
    'fallthrough', 'if', 'range', 'type', 'continue', 'for', 'import', 'return',
    'var', 'true', 'false', 'nil', 'main', 'fmt', 'math', 'strings'
}

# Random name generator with 6 letters
def generar_nombre():
    return ''.join(random.choices(string.ascii_lowercase, k=6))

# Generate random AES key
def generar_clave_aes():
    """Generates a 32-byte AES key (256 bits)"""
    return os.urandom(32)

# Encrypt string with AES
def cifrar_string(texto, clave):
    """Encrypts a string using AES-256-CBC"""
    # Generate random IV
    iv = os.urandom(16)
    
    # Create cipher
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    
    # Encrypt text
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, AES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    # Combine IV + encrypted text and encode in base64
    resultado = iv + texto_cifrado
    return base64.b64encode(resultado).decode('utf-8')

# Check if a string contains important escape characters
def contiene_escape_importante(cadena):
    """Checks if a string contains escape characters that shouldn't be obfuscated"""
    escapes_importantes = ['\\n', '\\t', '\\r', '\\f', '\\v', '\\a', '\\b']
    return any(escape in cadena for escape in escapes_importantes)

# Generate Go code for AES decryption
def generar_codigo_descifrado(clave):
    """Generates the Go code needed to decrypt the strings"""
    clave_b64 = base64.b64encode(clave).decode('utf-8')
    
    codigo_go = f'''
var encryptionKey = "{clave_b64}"

func decryptString(encryptedText string) string {{
	// Decode key
	keyBytes, _ := base64.StdEncoding.DecodeString(encryptionKey)
	
	// Decode encrypted text
	data, _ := base64.StdEncoding.DecodeString(encryptedText)
	
	// Extract IV (first 16 bytes)
	iv := data[:16]
	encryptedBytes := data[16:]
	
	// Create cipher
	block, _ := aes.NewCipher(keyBytes)
	mode := cipher.NewCBCDecrypter(block, iv)
	
	// Decrypt
	decryptedText := make([]byte, len(encryptedBytes))
	mode.CryptBlocks(decryptedText, encryptedBytes)
	
	// Remove PKCS7 padding
	lastByte := decryptedText[len(decryptedText)-1]
	if lastByte > 0 && lastByte <= 16 {{
		// Check if it's valid padding
		isValidPadding := true
		for i := len(decryptedText) - int(lastByte); i < len(decryptedText); i++ {{
			if decryptedText[i] != lastByte {{
				isValidPadding = false
				break
			}}
		}}
		if isValidPadding {{
			decryptedText = decryptedText[:len(decryptedText)-int(lastByte)]
		}}
	}}
	
	return string(decryptedText)
}}
'''
    return codigo_go

# Extract renamable identifiers (funcs, types, vars, consts, receivers)
def extraer_identificadores(codigo):
    # First, extract and protect imports
    import_pattern = r'import\s*\(([\s\S]*?)\)'
    imports = re.findall(import_pattern, codigo)
    
    # Create a temporary version of the code without imports for analysis
    codigo_sin_imports = re.sub(import_pattern, 'IMPORT_BLOCK', codigo)
    
    patterns = [
        r'\bfunc\s+(\w+)\s*\(',                      # Functions
        r'\btype\s+(\w+)\s+(struct|interface)',      # Structs / Interfaces
        r'\bvar\s+(\w+)',                            # Variables
        r'\bconst\s+(\w+)',                          # Constants
        r'\bfunc\s*\(\s*(\w+)\s+\*\w+\s*\)'         # Type receivers (x *Type)
    ]

    found = set()
    for pattern in patterns:
        found.update(re.findall(pattern, codigo_sin_imports))

    names = set()
    for e in found:
        if isinstance(e, tuple):
            names.add(e[0])
        else:
            names.add(e)

    return {n for n in names if n not in RESERVED}

# Replace names in code and in doc-style comments
def reemplazar_nombres(codigo, tabla):
    # Protect imports before replacing
    import_pattern = r'import\s*\(([\s\S]*?)\)'
    imports = re.findall(import_pattern, codigo)
    
    # Replace imports with temporary markers
    codigo_protegido = re.sub(import_pattern, 'IMPORT_BLOCK', codigo)
    
    # Apply replacements
    for original, nuevo in tabla.items():
        codigo_protegido = re.sub(rf'\b{original}\b', nuevo, codigo_protegido)
        codigo_protegido = re.sub(rf'(//\s*){original}\b', rf'\1{nuevo}', codigo_protegido)
    
    # Restore original imports
    for import_block in imports:
        codigo_protegido = codigo_protegido.replace('IMPORT_BLOCK', f'import (\n\t{import_block}\n)', 1)
    
    return codigo_protegido

# Replace strings with getStr(idx) using AES encryption
def reemplazar_strings(codigo):
    # Protect imports before processing strings
    import_pattern = r'import\s*\(([\s\S]*?)\)'
    imports = re.findall(import_pattern, codigo)
    
    # Replace imports with temporary markers
    codigo_protegido = re.sub(import_pattern, 'IMPORT_BLOCK', codigo)
    
    # Protect constants
    const_pattern = r'const\s*\(([\s\S]*?)\)'
    const_blocks = re.findall(const_pattern, codigo_protegido)
    codigo_sin_const = re.sub(const_pattern, 'CONST_BLOCK', codigo_protegido)
    
    strings = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', codigo_sin_const)
    
    if not strings:
        # If no strings, restore blocks and return
        for const_block in const_blocks:
            codigo_sin_const = codigo_sin_const.replace('CONST_BLOCK', f'const (\n\t{const_block}\n)', 1)
        
        # Restore original imports
        for import_block in imports:
            codigo_sin_const = codigo_sin_const.replace('IMPORT_BLOCK', f'import (\n\t{import_block}\n)', 1)
        
        return codigo_sin_const
    
    # Filter strings containing important escapes
    obfuscatable_strings = []
    protected_strings = []
    
    for string in strings:
        if contiene_escape_importante(string):
            protected_strings.append(string)
        else:
            obfuscatable_strings.append(string)
    
    # If no strings to obfuscate, return original code
    if not obfuscatable_strings:
        # Restore constant blocks
        for const_block in const_blocks:
            codigo_sin_const = codigo_sin_const.replace('CONST_BLOCK', f'const (\n\t{const_block}\n)', 1)
        
        # Restore original imports
        for import_block in imports:
            codigo_sin_const = codigo_sin_const.replace('IMPORT_BLOCK', f'import (\n\t{import_block}\n)', 1)
        
        return codigo_sin_const
    
    # Generate AES key
    clave_aes = generar_clave_aes()
    
    # Encrypt unique strings
    unique_strings = sorted(set(obfuscatable_strings))
    encrypted_strings = []
    
    for s in unique_strings:
        encrypted_text = cifrar_string(s, clave_aes)
        encrypted_strings.append(f'"{encrypted_text}"')
    
    # Create string map
    mapa = {s: i for i, s in enumerate(unique_strings)}
    
    # Replace only obfuscatable strings in the code
    for s, idx in mapa.items():
        codigo_sin_const = codigo_sin_const.replace(f'"{s}"', f'getStr({idx})')
    
    # Restore constant blocks
    for const_block in const_blocks:
        codigo_sin_const = codigo_sin_const.replace('CONST_BLOCK', f'const (\n\t{const_block}\n)', 1)
    
    # Restore original imports and add necessary imports for encryption
    for import_block in imports:
        codigo_sin_const = codigo_sin_const.replace('IMPORT_BLOCK', f'import (\n\t{import_block}\n)', 1)
    
    # Add crypto imports if they don't exist
    if 'crypto/aes' not in codigo_sin_const:
        # Search for existing import block
        import_match = re.search(r'import\s*\(([\s\S]*?)\)', codigo_sin_const)
        if import_match:
            existing_imports = import_match.group(1)
            new_imports = existing_imports + '\n\t"crypto/aes"\n\t"crypto/cipher"\n\t"encoding/base64"'
            codigo_sin_const = re.sub(r'import\s*\([^)]*\)', f'import (\n\t{new_imports}\n)', codigo_sin_const, flags=re.DOTALL)
    
    # Generate Go decryption code
    codigo_descifrado = generar_codigo_descifrado(clave_aes)
    
    # getStr function that uses decryption - format to avoid very long lines
    formatted_strings = []
    for i, string in enumerate(encrypted_strings):
        formatted_strings.append(f'\n\t\t{string}, // {i}')
    
    func = f"\nfunc getStr(i int) string {{\n\treturn decryptString([...]string{{{''.join(formatted_strings)}\n\t}}[i])\n}}\n"
    
    return codigo_sin_const + codigo_descifrado + func

# Remove line comments and duplicate empty lines
def limpiar_basura(codigo):
    codigo = re.sub(r'//.*', '', codigo)            # Line comments
    codigo = re.sub(r'\n\s*\n+', '\n', codigo)      # Multiple empty lines
    return codigo

# Main process
def ofuscar_go(archivo):
    if not os.path.exists(archivo):
        print("❌ File does not exist.")
        return

    with open(archivo, 'r', encoding='utf-8') as f:
        codigo = f.read()

    nombres = extraer_identificadores(codigo)
    tabla = {}
    print()
    for nombre in nombres:
        nuevo = generar_nombre()
        while nuevo in tabla.values():
            nuevo = generar_nombre()
        tabla[nombre] = nuevo
        print(f"Renaming: {nombre} → {nuevo}")

    codigo = reemplazar_nombres(codigo, tabla)
    codigo = reemplazar_strings(codigo)
    codigo = limpiar_basura(codigo)

    nuevo_archivo = archivo.replace('.go', '_obfuscated.go')
    with open(nuevo_archivo, 'w', encoding='utf-8') as f:
        f.write(codigo)

    print(f"\n✅ Obfuscated file saved as: {nuevo_archivo}")
    print("🔐 Strings encrypted with AES-256-CBC")
    print("🔑 Encryption key randomly generated")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 obfuscator.py <file.go>")
        sys.exit(1)
    archivo = sys.argv[1]
    ofuscar_go(archivo)
