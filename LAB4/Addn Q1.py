from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time

# -----------------------------
# Key Management
# -----------------------------
class DRMKeyManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.master_key = None
        self.generate_master_key()
        self.revoked = False

    def generate_master_key(self):
        self.master_key = ElGamal.generate(self.key_size, get_random_bytes)
        self.revoked = False
        print(f"[INFO] Master ElGamal key generated ({self.key_size}-bit).")

    def revoke_key(self):
        self.revoked = True
        print("[WARNING] Master key revoked!")

    def renew_key(self):
        print("[INFO] Renewing master key...")
        self.generate_master_key()

# -----------------------------
# Content Encryption & Access
# -----------------------------
class ContentManager:
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.content_store = {}          # id -> encrypted content
        self.access_control = {}         # user -> list of content ids with access

    def upload_content(self, content_id, plaintext_bytes):
        if self.key_manager.revoked:
            raise ValueError("Cannot encrypt: master key revoked.")
        key = self.key_manager.master_key.publickey()
        # Encrypt each byte individually (ElGamal only supports small ints)
        cipher_bytes = []
        for b in plaintext_bytes:
            k = random.StrongRandom().randint(1, key.p-2)
            c1 = pow(key.g, k, key.p)
            c2 = (b * pow(key.y, k, key.p)) % key.p
            cipher_bytes.append((c1, c2))
        self.content_store[content_id] = cipher_bytes
        print(f"[INFO] Content '{content_id}' encrypted and stored.")

    def grant_access(self, user, content_id):
        self.access_control.setdefault(user, set()).add(content_id)
        print(f"[INFO] Access granted to '{user}' for content '{content_id}'.")

    def revoke_access(self, user, content_id):
        self.access_control.get(user, set()).discard(content_id)
        print(f"[INFO] Access revoked for '{user}' on content '{content_id}'.")

    def decrypt_content(self, user, content_id):
        if content_id not in self.access_control.get(user, set()):
            raise PermissionError("Access denied for this content.")
        if self.key_manager.revoked:
            raise ValueError("Cannot decrypt: master key revoked.")

        cipher_bytes = self.content_store[content_id]
        priv = self.key_manager.master_key
        decrypted = bytearray()
        for c1, c2 in cipher_bytes:
            s = pow(c1, priv.x, priv.p)
            s_inv = pow(s, -1, priv.p)
            b = (c2 * s_inv) % priv.p
            decrypted.append(b)
        return bytes(decrypted)

# -----------------------------
# Demo Usage
# -----------------------------
if __name__ == "__main__":
    drm = DRMKeyManager()
    cm = ContentManager(drm)

    # Upload some content
    sample_text = b"Top Secret Movie Content"
    cm.upload_content("movie1", sample_text)

    # Grant access to user
    cm.grant_access("Alice", "movie1")

    # User decrypts content
    decrypted = cm.decrypt_content("Alice", "movie1")
    print("[DECRYPTED] ", decrypted.decode())

    # Revoke key and attempt access
    drm.revoke_key()
    try:
        cm.decrypt_content("Alice", "movie1")
    except ValueError as e:
        print("[ERROR] ", e)

    # Renew key and re-upload content
    drm.renew_key()
    cm.upload_content("movie2", b"New Movie Content")
    cm.grant_access("Bob", "movie2")
    decrypted2 = cm.decrypt_content("Bob", "movie2")
    print("[DECRYPTED] ", decrypted2.decode())
