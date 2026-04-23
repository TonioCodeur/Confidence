"""
crypto.py — Moteur de chiffrement/déchiffrement pour l'application Confidence.

Utilise la bibliothèque `cryptography` avec :
- Dérivation de clé : PBKDF2-HMAC-SHA256 (600 000 itérations)
- Chiffrement : Fernet (AES-128-CBC + HMAC-SHA256, via la couche haut niveau)

Format du fichier .enc :
    [4 octets : magic "CONF"]
    [16 octets : salt PBKDF2]
    [N octets : jeton Fernet (données chiffrées)]

Auteur : DB (moteur de chiffrement)
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

MAGIC = b"CONF"          # Signature de fichier (4 octets)
SALT_LENGTH = 16          # Longueur du salt en octets
KDF_ITERATIONS = 600_000  # Nombre d'itérations PBKDF2 (recommandation OWASP 2024+)

# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------


def _derive_key(password: str, salt: bytes) -> bytes:
    """Dérive une clé Fernet (base64-url, 32 octets bruts) à partir d'un mot
    de passe arbitraire et d'un salt via PBKDF2-HMAC-SHA256.

    Args:
        password: Mot de passe fourni par l'utilisateur (chaîne arbitraire).
        salt: Salt aléatoire de *SALT_LENGTH* octets.

    Returns:
        Clé encodée en base64-url prête à être utilisée par Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    # Fernet attend une clé de 32 octets encodée en base64-url-safe
    return base64.urlsafe_b64encode(raw_key)


def _read_file(filepath: str) -> bytes:
    """Lit un fichier en mode binaire.

    Raises:
        FileNotFoundError: Le fichier n'existe pas.
        PermissionError: Droits insuffisants.
        OSError: Toute autre erreur d'E/S.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")
    if not path.is_file():
        raise ValueError(f"Le chemin ne désigne pas un fichier : {filepath}")
    return path.read_bytes()


def _write_file(filepath: str, data: bytes) -> None:
    """Écrit des données binaires dans un fichier, en créant les répertoires
    parents si nécessaire."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _output_path_for_decryption(original_path: str) -> str:
    """Détermine le chemin de sortie lors du déchiffrement.

    - Retire l'extension `.enc` si elle est présente.
    - Si le fichier résultant existe déjà, ajoute le suffixe ``_decrypted``
      avant l'extension pour éviter l'écrasement.

    Exemples :
        document.txt.enc  ->  document.txt         (si libre)
        document.txt.enc  ->  document_decrypted.txt  (si document.txt existe)
    """
    path = Path(original_path)

    if path.suffix.lower() == ".enc":
        base_path = path.with_suffix("")  # retire .enc
    else:
        # Cas improbable : pas d'extension .enc, on ajoute _decrypted
        base_path = path.with_name(path.stem + "_decrypted" + path.suffix)

    if not base_path.exists():
        return str(base_path)

    # Collision : insérer _decrypted avant l'extension finale
    stem = base_path.stem
    suffix = base_path.suffix
    decrypted_path = base_path.with_name(f"{stem}_decrypted{suffix}")
    return str(decrypted_path)


# ---------------------------------------------------------------------------
# Fonctions publiques
# ---------------------------------------------------------------------------


def encrypt_file(filepath: str, key: str) -> str:
    """Chiffre un fichier et écrit le résultat dans ``<filepath>.enc``.

    Le fichier chiffré utilise le format :
        ``[MAGIC 4B][SALT 16B][FERNET_TOKEN NB]``

    Args:
        filepath: Chemin du fichier en clair à chiffrer.
        key: Mot de passe / phrase de passe fourni par l'utilisateur.

    Returns:
        Chemin absolu du fichier chiffré (``<filepath>.enc``).

    Raises:
        FileNotFoundError: Le fichier source n'existe pas.
        ValueError: Le fichier semble déjà chiffré (magic CONF détecté) ou
            la clé est vide.
        OSError: Erreur d'écriture du fichier de sortie.
    """
    # --- Validations ---
    if not key:
        raise ValueError("La clé de chiffrement ne peut pas être vide.")

    plaintext = _read_file(filepath)

    # Vérifier que le fichier n'est pas déjà au format CONF
    if plaintext[:4] == MAGIC:
        raise ValueError(
            f"Le fichier semble déjà chiffré (en-tête CONF détecté) : {filepath}"
        )

    # --- Dérivation de clé ---
    salt = os.urandom(SALT_LENGTH)
    fernet_key = _derive_key(key, salt)
    fernet = Fernet(fernet_key)

    # --- Chiffrement ---
    token = fernet.encrypt(plaintext)

    # --- Écriture du fichier .enc ---
    output_path = filepath + ".enc"
    encrypted_data = MAGIC + salt + token
    _write_file(output_path, encrypted_data)

    return str(Path(output_path).resolve())


def decrypt_file(filepath: str, key: str) -> str:
    """Déchiffre un fichier ``.enc`` produit par :func:`encrypt_file`.

    Args:
        filepath: Chemin du fichier chiffré (``.enc``).
        key: Mot de passe / phrase de passe utilisé lors du chiffrement.

    Returns:
        Chemin absolu du fichier déchiffré.

    Raises:
        FileNotFoundError: Le fichier chiffré n'existe pas.
        ValueError: Format invalide (magic absent, fichier trop court, clé
            vide).
        PermissionError: Clé incorrecte ou fichier corrompu (impossible de
            déchiffrer).
    """
    # --- Validations ---
    if not key:
        raise ValueError("La clé de déchiffrement ne peut pas être vide.")

    raw = _read_file(filepath)

    min_size = len(MAGIC) + SALT_LENGTH + 1  # au moins 1 octet de données
    if len(raw) < min_size:
        raise ValueError(
            f"Fichier trop court pour être un fichier chiffré valide : {filepath}"
        )

    # --- Lecture de l'en-tête ---
    magic = raw[: len(MAGIC)]
    if magic != MAGIC:
        raise ValueError(
            f"Format de fichier invalide (en-tête CONF manquant) : {filepath}. "
            "Ce fichier n'a pas été chiffré par cette application."
        )

    salt = raw[len(MAGIC) : len(MAGIC) + SALT_LENGTH]
    token = raw[len(MAGIC) + SALT_LENGTH :]

    # --- Dérivation de clé ---
    fernet_key = _derive_key(key, salt)
    fernet = Fernet(fernet_key)

    # --- Déchiffrement ---
    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken:
        raise PermissionError(
            "Déchiffrement impossible : clé incorrecte ou fichier corrompu."
        )

    # --- Écriture du fichier déchiffré ---
    output_path = _output_path_for_decryption(filepath)
    _write_file(output_path, plaintext)

    return str(Path(output_path).resolve())


def verify_key(filepath: str, key: str) -> bool:
    """Vérifie si une clé est correcte pour un fichier chiffré, sans écrire
    de fichier de sortie.

    Args:
        filepath: Chemin du fichier chiffré (``.enc``).
        key: Mot de passe à vérifier.

    Returns:
        ``True`` si la clé permet de déchiffrer le fichier, ``False`` sinon.

    Raises:
        FileNotFoundError: Le fichier n'existe pas.
        ValueError: Le fichier n'est pas au format attendu.
    """
    if not key:
        return False

    raw = _read_file(filepath)

    min_size = len(MAGIC) + SALT_LENGTH + 1
    if len(raw) < min_size:
        raise ValueError(
            f"Fichier trop court pour être un fichier chiffré valide : {filepath}"
        )

    magic = raw[: len(MAGIC)]
    if magic != MAGIC:
        raise ValueError(
            f"Format de fichier invalide (en-tête CONF manquant) : {filepath}"
        )

    salt = raw[len(MAGIC) : len(MAGIC) + SALT_LENGTH]
    token = raw[len(MAGIC) + SALT_LENGTH :]

    fernet_key = _derive_key(key, salt)
    fernet = Fernet(fernet_key)

    try:
        fernet.decrypt(token)
        return True
    except InvalidToken:
        return False
